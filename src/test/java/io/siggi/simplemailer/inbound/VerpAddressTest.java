package io.siggi.simplemailer.inbound;

import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.RecipientResult;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerpAddressTest {
    private static final String ID = "0b7c5a6e-3f1d-4c2a-9e8b-1a2b3c4d5e6f";
    private final VerpAddress verp = new VerpAddress("Bounces.Example.com", "s3cret");

    private static String expectedTag(String secret, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(data.getBytes(StandardCharsets.US_ASCII)), 0, 8);
    }

    @Test
    void encodesDocumentedFormat() throws Exception {
        String address = verp.encode(ID, 3);
        assertEquals("bounce+0b7c5a6e3f1d4c2a9e8b1a2b3c4d5e6f.3." + expectedTag("s3cret", ID + ".3")
                + "@bounces.example.com", address);
        // RFC 5321 local-part limit, even for a large recipient index
        String big = verp.encode(ID, VerpAddress.MAX_RECIPIENT_INDEX);
        assertEquals(64, big.indexOf('@'), big);
        assertTrue(verp.verify(big).valid());
    }

    @Test
    void roundTrips() {
        for (int i : new int[]{0, 1, 42, 123456}) {
            VerpAddress.Verification v = verp.verify(verp.encode(ID, i));
            assertTrue(v.valid());
            assertEquals(ID, v.address().jobId());
            assertEquals(i, v.address().recipientIndex());
        }
    }

    @Test
    void acceptsAngleBracketsAndAnyCase() {
        String address = verp.encode(ID.toUpperCase(Locale.ROOT), 2);
        assertTrue(verp.verify("<" + address + ">").valid());
        VerpAddress.Verification upper = verp.verify(address.toUpperCase(Locale.ROOT));
        assertTrue(upper.valid());
        assertEquals(ID, upper.address().jobId());
        assertTrue(verp.verify(address + ".").valid(), "trailing root dot on domain");
    }

    @Test
    void rejectsForgedOrAlteredTags() {
        String address = verp.encode(ID, 1);
        // other recipient index, same tag
        String otherIndex = address.replace("." + 1 + ".", ".2.");
        assertEquals(VerpAddress.Status.BAD_TAG, verp.verify(otherIndex).status());
        // other job, same tag
        String otherJob = address.replace("0b7c5a6e", "0b7c5a6f");
        assertEquals(VerpAddress.Status.BAD_TAG, verp.verify(otherJob).status());
        // tag flipped
        int at = address.indexOf('@');
        char last = address.charAt(at - 1);
        String flipped = address.substring(0, at - 1) + (last == '0' ? '1' : '0') + address.substring(at);
        assertEquals(VerpAddress.Status.BAD_TAG, verp.verify(flipped).status());
        // different secret
        VerpAddress other = new VerpAddress("bounces.example.com", "other");
        assertEquals(VerpAddress.Status.BAD_TAG, other.verify(address).status());
        assertNull(verp.verify(otherIndex).address());
    }

    @Test
    void rejectsNonBounceAddresses() {
        String good = verp.encode(ID, 1);
        String tagAndDomain = good.substring(good.lastIndexOf('.', good.indexOf('@')));
        for (String bad : new String[]{
                null, "", "user@bounces.example.com", "postmaster@bounces.example.com",
                good.replace("@bounces.example.com", "@example.com"),
                good.replace("@bounces.example.com", "@evil.bounces.example.com"),
                good.replace("bounce+", "bounces+"),
                good.replace("bounce+", "x+"),
                // dashed uuid, leading zero / negative / missing index, short tag, no domain
                "bounce+" + ID + ".1" + tagAndDomain,
                good.replace(".1.", ".01."),
                good.replace(".1.", ".-1."),
                good.replace(".1.", ".."),
                good.substring(0, good.indexOf('@') - 1) + good.substring(good.indexOf('@')),
                good.substring(0, good.indexOf('@')),
                "bounce+0b7c5a6e3f1d4c2a9e8b1a2b3c4d5e6f.9999999999" + tagAndDomain,
        }) {
            VerpAddress.Verification v = verp.verify(bad);
            assertEquals(VerpAddress.Status.NOT_BOUNCE_ADDRESS, v.status(), String.valueOf(bad));
            assertFalse(v.valid());
        }
    }

    @Test
    void encodeRejectsBadInput() {
        assertThrows(IllegalArgumentException.class, () -> verp.encode("not-a-uuid", 0));
        assertThrows(IllegalArgumentException.class, () -> verp.encode(ID, -1));
        assertThrows(IllegalArgumentException.class, () -> verp.encode(ID, VerpAddress.MAX_RECIPIENT_INDEX + 1));
        assertThrows(IllegalArgumentException.class, () -> new VerpAddress(" ", "x"));
        assertThrows(IllegalArgumentException.class, () -> new VerpAddress("b.example.com", ""));
    }

    @Test
    void fromConfigNeedsDomainAndSecret() throws Exception {
        assertNull(VerpAddress.fromConfig(Config.fromJson("{}")));
        assertNull(VerpAddress.fromConfig(Config.fromJson("{\"bounces\": {\"domain\": \"b.example.com\"}}")));
        // intake disabled, but domain and secret set: MAIL FROM is still VERP (PLAN.md §6a)
        VerpAddress v = VerpAddress.fromConfig(Config.fromJson(
                "{\"bounces\": {\"domain\": \"b.example.com\", \"secret\": \"k\"}}"));
        assertNotNull(v);
        assertEquals("b.example.com", v.domain());
    }

    @Test
    void envelopeSenderIsPerRecipient() {
        Job job = new Job();
        job.id = ID;
        RecipientResult a = new RecipientResult("a@x.test", 0);
        RecipientResult b = new RecipientResult("b@x.test", 1);
        var sender = verp.envelopeSender();
        assertEquals(verp.encode(ID, 0), sender.reversePath(job, a));
        assertEquals(verp.encode(ID, 1), sender.reversePath(job, b));
        assertNotEquals(sender.reversePath(job, a), sender.reversePath(job, b));
    }
}
