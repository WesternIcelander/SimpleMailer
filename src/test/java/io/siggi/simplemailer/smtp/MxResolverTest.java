package io.siggi.simplemailer.smtp;

import io.siggi.simplemailer.smtp.MxResolver.MxException;
import io.siggi.simplemailer.smtp.MxResolver.MxHost;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MxResolverTest {
    /** Fake DNS: records keyed by "name TYPE"; names in {@code existing} answer NODATA, others NXDOMAIN. */
    private static class FakeDns implements MxResolver.DnsLookup {
        final Map<String, List<String>> records = new HashMap<>();
        final Set<String> existing = new HashSet<>();
        final Set<String> failing = new HashSet<>();
        final List<String> queries = new ArrayList<>();

        FakeDns add(String name, String type, String... data) {
            records.put(name + " " + type, List.of(data));
            existing.add(name);
            return this;
        }

        @Override
        public List<String> lookup(String name, String type) throws IOException {
            queries.add(name + " " + type);
            if (failing.contains(name)) throw new IOException("SERVFAIL");
            List<String> r = records.get(name + " " + type);
            if (r != null) return r;
            if (existing.contains(name)) return List.of();
            throw new MxResolver.NameNotFound(name);
        }
    }

    private static MxResolver resolver(FakeDns dns, long seed) {
        return new MxResolver(dns, host -> new InetAddress[]{InetAddress.getByName("192.0.2.1")}, new Random(seed));
    }

    private static List<String> hosts(List<MxHost> mx) {
        return mx.stream().map(MxHost::host).toList();
    }

    @Test
    void sortsByPreference() throws Exception {
        FakeDns dns = new FakeDns().add("example.org", "MX",
                "20 mx2.example.org.", "10 MX1.Example.Org.", "30 mx3.example.org.");
        List<MxHost> mx = resolver(dns, 1).resolve("Example.ORG");
        assertEquals(List.of("mx1.example.org", "mx2.example.org", "mx3.example.org"), hosts(mx));
        assertEquals(10, mx.get(0).preference());
        assertFalse(mx.get(0).implicit());
    }

    @Test
    void randomisesTiesButKeepsPreferenceOrder() throws Exception {
        FakeDns dns = new FakeDns().add("example.org", "MX",
                "10 a.example.org.", "10 b.example.org.", "10 c.example.org.", "5 first.example.org.",
                "50 last.example.org.");
        Set<List<String>> orders = new HashSet<>();
        for (long seed = 0; seed < 50; seed++) {
            List<String> h = hosts(resolver(dns, seed).resolve("example.org"));
            assertEquals("first.example.org", h.get(0));
            assertEquals("last.example.org", h.get(4));
            assertEquals(Set.of("a.example.org", "b.example.org", "c.example.org"), new HashSet<>(h.subList(1, 4)));
            orders.add(h);
        }
        assertTrue(orders.size() > 1, "ties should be shuffled");
    }

    @Test
    void duplicateExchangesAreCollapsed() throws Exception {
        FakeDns dns = new FakeDns().add("example.org", "MX", "10 mx.example.org.", "10 mx.example.org");
        assertEquals(List.of("mx.example.org"), hosts(resolver(dns, 1).resolve("example.org")));
    }

    @Test
    void fallsBackToARecord() throws Exception {
        FakeDns dns = new FakeDns().add("example.org", "A", "192.0.2.10");
        List<MxHost> mx = resolver(dns, 1).resolve("example.org");
        assertEquals(List.of(new MxHost("example.org", 0, true)), mx);
    }

    @Test
    void fallsBackToAaaaRecord() throws Exception {
        FakeDns dns = new FakeDns().add("example.org", "AAAA", "2001:db8::1");
        assertEquals(List.of(new MxHost("example.org", 0, true)), resolver(dns, 1).resolve("example.org"));
    }

    @Test
    void noMxAndNoAddressIsPermanent() {
        FakeDns dns = new FakeDns().add("example.org", "TXT", "v=spf1 -all");
        MxException e = assertThrows(MxException.class, () -> resolver(dns, 1).resolve("example.org"));
        assertEquals(MxException.Kind.NO_MAIL_HOST, e.kind());
        assertTrue(e.isPermanent());
    }

    @Test
    void nullMxIsPermanentAndSkipsAddressFallback() {
        FakeDns dns = new FakeDns().add("example.org", "MX", "0 .").add("example.org", "A", "192.0.2.10");
        MxException e = assertThrows(MxException.class, () -> resolver(dns, 1).resolve("example.org"));
        assertEquals(MxException.Kind.NULL_MX, e.kind());
        assertTrue(e.isPermanent());
        assertFalse(dns.queries.contains("example.org A"));
    }

    @Test
    void nullMxMixedWithRealRecordsUsesTheRealOnes() throws Exception {
        FakeDns dns = new FakeDns().add("example.org", "MX", "0 .", "10 mx.example.org.");
        assertEquals(List.of("mx.example.org"), hosts(resolver(dns, 1).resolve("example.org")));
    }

    @Test
    void nxdomainIsPermanent() {
        MxException e = assertThrows(MxException.class, () -> resolver(new FakeDns(), 1).resolve("nope.example"));
        assertEquals(MxException.Kind.NO_SUCH_DOMAIN, e.kind());
        assertTrue(e.isPermanent());
    }

    @Test
    void servfailIsTemporary() {
        FakeDns dns = new FakeDns().add("example.org", "MX", "10 mx.example.org.");
        dns.failing.add("example.org");
        MxException e = assertThrows(MxException.class, () -> resolver(dns, 1).resolve("example.org"));
        assertEquals(MxException.Kind.TEMPORARY, e.kind());
        assertFalse(e.isPermanent());
    }

    @Test
    void servfailDuringAddressFallbackIsTemporary() {
        FakeDns dns = new FakeDns() {
            @Override
            public List<String> lookup(String name, String type) throws IOException {
                if (type.equals("A")) throw new IOException("timeout");
                return super.lookup(name, type);
            }
        };
        dns.existing.add("example.org");
        MxException e = assertThrows(MxException.class, () -> resolver(dns, 1).resolve("example.org"));
        assertEquals(MxException.Kind.TEMPORARY, e.kind());
    }

    @Test
    void followsCnameForMx() throws Exception {
        FakeDns dns = new FakeDns().add("alias.example.org", "CNAME", "real.example.net.")
                .add("real.example.net", "MX", "10 mx.example.net.");
        assertEquals(List.of("mx.example.net"), hosts(resolver(dns, 1).resolve("alias.example.org")));
    }

    @Test
    void cnameLoopEndsInNoMailHost() {
        FakeDns dns = new FakeDns().add("a.example.org", "CNAME", "b.example.org.")
                .add("b.example.org", "CNAME", "a.example.org.");
        MxException e = assertThrows(MxException.class, () -> resolver(dns, 1).resolve("a.example.org"));
        assertEquals(MxException.Kind.NO_MAIL_HOST, e.kind());
    }

    @Test
    void internationalisedDomainIsQueriedAsPunycode() throws Exception {
        FakeDns dns = new FakeDns().add("xn--bcher-kva.example", "MX", "10 mx.xn--bcher-kva.example.");
        assertEquals(List.of("mx.xn--bcher-kva.example"), hosts(resolver(dns, 1).resolve("bücher.example")));
    }

    @Test
    void addressLiteralsNeedNoDns() throws Exception {
        FakeDns dns = new FakeDns();
        assertEquals(List.of(new MxHost("192.0.2.7", 0, true)), resolver(dns, 1).resolve("[192.0.2.7]"));
        assertEquals(List.of(new MxHost("2001:db8::7", 0, true)), resolver(dns, 1).resolve("[IPv6:2001:db8::7]"));
        assertTrue(dns.queries.isEmpty());
    }

    @Test
    void unparseableRecordsAreSkipped() {
        assertEquals(List.of(new MxHost("ok.example", 5, false)),
                MxResolver.parseMx(List.of("junk", "x mx.example.", "70000 big.example.", "5 ok.example."), "d"));
    }

    @Test
    void addressesUseTheAddressResolver() throws Exception {
        MxResolver r = resolver(new FakeDns(), 1);
        assertArrayEquals(new InetAddress[]{InetAddress.getByName("192.0.2.1")},
                r.addresses(new MxHost("mx.example.org", 10, false)));
    }
}
