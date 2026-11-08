package io.siggi.simplemailer.smtp;

import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.IOException;
import java.net.IDN;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Finds the mail exchangers for a recipient domain (PLAN.md §2, §5).
 *
 * <ul>
 *   <li>MX records are looked up through the JDK JNDI DNS provider and sorted by preference, with hosts of equal
 *       preference shuffled so load is spread across them.</li>
 *   <li>If the domain exists but has no MX records, the domain itself is the implicit MX (RFC 5321 §5.1), provided
 *       it has an A or AAAA record.</li>
 *   <li>A null MX ({@code 0 .}, RFC 7505) means the domain accepts no mail: {@link MxException} with
 *       {@link MxException.Kind#NULL_MX}, which is permanent.</li>
 *   <li>A non-existent domain, or one with neither MX nor address records, is a permanent failure; a DNS timeout or
 *       SERVFAIL is temporary, so the delivery is deferred.</li>
 * </ul>
 *
 * <p>Address literals ({@code [192.0.2.1]}, {@code [IPv6:2001:db8::1]}) are returned as their own implicit MX.
 */
public final class MxResolver {
    /** Maximum number of CNAME hops followed while looking up a domain's MX records. */
    public static final int MAX_CNAME_HOPS = 8;

    /** One mail exchanger. {@code implicit} is true for the A/AAAA fallback and for address literals. */
    public record MxHost(String host, int preference, boolean implicit) {
    }

    /** Why a domain has no usable mail exchanger. */
    public static final class MxException extends IOException {
        public enum Kind {
            /** The domain does not exist (NXDOMAIN). Permanent. */
            NO_SUCH_DOMAIN,
            /** The domain exists but has no MX, A or AAAA records. Permanent. */
            NO_MAIL_HOST,
            /** The domain publishes a null MX (RFC 7505): it accepts no mail. Permanent. */
            NULL_MX,
            /** DNS timed out or returned SERVFAIL. Temporary: retry later. */
            TEMPORARY
        }

        private final Kind kind;

        public MxException(Kind kind, String message) {
            super(message);
            this.kind = kind;
        }

        public MxException(Kind kind, String message, Throwable cause) {
            super(message, cause);
            this.kind = kind;
        }

        public Kind kind() {
            return kind;
        }

        public boolean isPermanent() {
            return kind != Kind.TEMPORARY;
        }
    }

    /** The domain name does not exist (NXDOMAIN). */
    public static final class NameNotFound extends IOException {
        public NameNotFound(String message) {
            super(message);
        }
    }

    /**
     * A DNS query. Returns the record data of the given type for the name, or an empty list if the name exists but
     * has none (NODATA). Throws {@link NameNotFound} for NXDOMAIN and any other {@link IOException} for a temporary
     * failure. For {@code MX} records each entry is {@code "preference exchange"}; a {@code CNAME} result is the
     * canonical name.
     */
    @FunctionalInterface
    public interface DnsLookup {
        List<String> lookup(String name, String type) throws IOException;
    }

    /** Resolves a mail exchanger host name to the addresses to connect to. */
    @FunctionalInterface
    public interface AddressResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private final DnsLookup dns;
    private final AddressResolver addressResolver;
    private final Random random;

    public MxResolver(DnsLookup dns, AddressResolver addressResolver, Random random) {
        this.dns = Objects.requireNonNull(dns);
        this.addressResolver = Objects.requireNonNull(addressResolver);
        this.random = random;
    }

    /** A resolver using the system's DNS servers via JNDI, and {@link InetAddress#getAllByName} for addresses. */
    public static MxResolver system() {
        return new MxResolver(new JndiDnsLookup(), InetAddress::getAllByName, null);
    }

    /**
     * The mail exchangers for {@code domain}, most preferred first.
     *
     * @throws MxException if the domain has no usable mail exchanger; see {@link MxException#isPermanent()}
     */
    public List<MxHost> resolve(String domain) throws MxException {
        if (domain == null || domain.isBlank()) {
            throw new MxException(MxException.Kind.NO_SUCH_DOMAIN, "empty domain");
        }
        String d = domain.trim();
        if (d.startsWith("[") && d.endsWith("]")) {
            String literal = d.substring(1, d.length() - 1);
            if (literal.regionMatches(true, 0, "IPv6:", 0, 5)) literal = literal.substring(5);
            return List.of(new MxHost(literal, 0, true));
        }
        String name = normalise(d);

        String queried = name;
        List<String> records = null;
        for (int hop = 0; ; hop++) {
            records = query(queried, "MX", domain);
            if (!records.isEmpty()) break;
            // Some resolvers hand back only the CNAME for an alias; follow it ourselves.
            List<String> cname = query(queried, "CNAME", domain);
            if (cname.isEmpty() || hop >= MAX_CNAME_HOPS) break;
            queried = normalise(cname.get(0));
        }

        List<MxHost> hosts = parseMx(records, domain);
        if (hosts == null) {
            throw new MxException(MxException.Kind.NULL_MX, domain + " does not accept mail (null MX)");
        }
        if (!hosts.isEmpty()) return sort(hosts);

        // No MX records: the domain itself is the implicit MX if it has an address (RFC 5321 §5.1).
        if (!query(queried, "A", domain).isEmpty() || !query(queried, "AAAA", domain).isEmpty()) {
            return List.of(new MxHost(name, 0, true));
        }
        throw new MxException(MxException.Kind.NO_MAIL_HOST, domain + " has no MX, A or AAAA records");
    }

    /** The addresses of a mail exchanger, in the order the system resolver returns them. */
    public InetAddress[] addresses(MxHost host) throws UnknownHostException {
        return addressResolver.resolve(host.host());
    }

    private List<String> query(String name, String type, String domain) throws MxException {
        try {
            List<String> r = dns.lookup(name, type);
            return r == null ? List.of() : r;
        } catch (NameNotFound e) {
            throw new MxException(MxException.Kind.NO_SUCH_DOMAIN, domain + " does not exist", e);
        } catch (IOException | RuntimeException e) {
            throw new MxException(MxException.Kind.TEMPORARY,
                    "DNS " + type + " lookup for " + name + " failed: " + e.getMessage(), e);
        }
    }

    /**
     * Parses MX record data. Returns {@code null} for a null MX, and drops unparseable records. A {@code "."}
     * exchange mixed with real ones is invalid per RFC 7505; the real ones are used.
     */
    static List<MxHost> parseMx(List<String> records, String domain) {
        List<MxHost> hosts = new ArrayList<>();
        boolean sawNull = false;
        for (String record : records) {
            if (record == null) continue;
            String[] parts = record.trim().split("\\s+");
            if (parts.length != 2) continue;
            int preference;
            try {
                preference = Integer.parseInt(parts[0]);
            } catch (NumberFormatException e) {
                continue;
            }
            if (preference < 0 || preference > 65535) continue;
            String exchange = parts[1];
            if (exchange.equals(".") || exchange.isEmpty()) {
                sawNull = true;
                continue;
            }
            try {
                hosts.add(new MxHost(normalise(exchange), preference, false));
            } catch (MxException e) {
                // invalid host name in the record: skip it
            }
        }
        if (hosts.isEmpty() && sawNull) return null;
        return hosts;
    }

    private List<MxHost> sort(List<MxHost> hosts) {
        Random r = random != null ? random : ThreadLocalRandom.current();
        Map<Integer, List<MxHost>> byPreference = new LinkedHashMap<>();
        for (MxHost h : hosts) {
            List<MxHost> group = byPreference.computeIfAbsent(h.preference(), k -> new ArrayList<>());
            if (group.stream().noneMatch(g -> g.host().equals(h.host()))) group.add(h);
        }
        List<Integer> preferences = new ArrayList<>(byPreference.keySet());
        Collections.sort(preferences);
        List<MxHost> sorted = new ArrayList<>();
        for (int p : preferences) {
            List<MxHost> group = byPreference.get(p);
            Collections.shuffle(group, r);
            sorted.addAll(group);
        }
        return List.copyOf(sorted);
    }

    /** Lower-cases, strips a trailing dot and converts an internationalised name to its ASCII form. */
    private static String normalise(String name) throws MxException {
        String n = name.trim();
        if (n.endsWith(".")) n = n.substring(0, n.length() - 1);
        if (n.isEmpty()) throw new MxException(MxException.Kind.NO_SUCH_DOMAIN, "empty domain");
        try {
            return IDN.toASCII(n, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            throw new MxException(MxException.Kind.NO_SUCH_DOMAIN, "invalid domain " + name, e);
        }
    }

    /** {@link DnsLookup} using the JDK's JNDI DNS provider and the system's configured name servers. */
    public static final class JndiDnsLookup implements DnsLookup {
        private final Hashtable<String, String> env = new Hashtable<>();

        public JndiDnsLookup() {
            this("dns:");
        }

        /** @param providerUrl e.g. {@code "dns:"} for the system resolvers or {@code "dns://192.0.2.53"} */
        public JndiDnsLookup(String providerUrl) {
            env.put(DirContext.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
            env.put(DirContext.PROVIDER_URL, providerUrl);
            env.put("com.sun.jndi.dns.timeout.initial", "2000");
            env.put("com.sun.jndi.dns.timeout.retries", "3");
        }

        @Override
        public List<String> lookup(String name, String type) throws IOException {
            DirContext ctx = null;
            try {
                ctx = new InitialDirContext(env);
                // Trailing dot: an absolute name, so no search domains are appended.
                Attributes attrs = ctx.getAttributes(name + ".", new String[]{type});
                Attribute attr = attrs.get(type);
                List<String> out = new ArrayList<>();
                if (attr != null) {
                    NamingEnumeration<?> values = attr.getAll();
                    while (values.hasMore()) out.add(String.valueOf(values.next()));
                }
                return out;
            } catch (NameNotFoundException e) {
                throw new NameNotFound(name + ": " + e.getExplanation());
            } catch (ServiceUnavailableException | CommunicationException e) {
                throw new IOException("DNS server unavailable: " + e.getExplanation(), e);
            } catch (NamingException e) {
                throw new IOException(e.getExplanation() == null ? e.toString() : e.getExplanation(), e);
            } finally {
                if (ctx != null) {
                    try {
                        ctx.close();
                    } catch (NamingException ignored) {
                    }
                }
            }
        }
    }
}
