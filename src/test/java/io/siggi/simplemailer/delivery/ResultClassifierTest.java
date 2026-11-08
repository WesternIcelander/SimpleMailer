package io.siggi.simplemailer.delivery;

import io.siggi.simplemailer.delivery.ResultClassifier.Classification;
import io.siggi.simplemailer.delivery.ResultClassifier.Kind;
import io.siggi.simplemailer.delivery.ResultClassifier.Phase;
import io.siggi.simplemailer.smtp.MxResolver;
import io.siggi.simplemailer.smtp.SmtpResponse;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResultClassifierTest {
    private static Classification c(int code, Phase phase) {
        return ResultClassifier.classify(new SmtpResponse(code, "x"), phase);
    }

    @Test
    void twoHundredsSucceed() {
        for (Phase p : Phase.values()) {
            Classification r = c(250, p);
            assertEquals(Kind.SUCCESS, r.kind(), p.name());
            assertNull(r.error());
        }
    }

    @Test
    void fiveHundredsArePermanentAndDecideTheRecipient() {
        for (Phase p : new Phase[]{Phase.MAIL, Phase.RCPT, Phase.DATA}) {
            Classification r = c(550, p);
            assertEquals(Kind.PERMANENT, r.kind(), p.name());
            assertEquals(DeliveryEngine.SMTP_PERMANENT_FAILURE, r.error());
            assertTrue(r.decides());
        }
        assertEquals(Kind.PERMANENT, c(554, Phase.DATA).kind());
    }

    @Test
    void fourHundredsAreTransient() {
        for (Phase p : Phase.values()) {
            Classification r = c(451, p);
            assertEquals(Kind.TRANSIENT, r.kind(), p.name());
            assertEquals(DeliveryEngine.SMTP_TEMPORARY_FAILURE, r.error());
            assertFalse(r.decides());
        }
    }

    @Test
    void sessionLevelFiveHundredMovesOnToTheNextMx() {
        Classification r = c(554, Phase.SESSION);
        assertEquals(Kind.PERMANENT, r.kind());
        assertFalse(r.decides());
    }

    @Test
    void rcpt552IsTreatedAs452() {
        Classification r = c(552, Phase.RCPT);
        assertEquals(Kind.TRANSIENT, r.kind());
        assertEquals(DeliveryEngine.SMTP_TEMPORARY_FAILURE, r.error());
        // but 552 to the message itself (too big) is permanent
        assertEquals(Kind.PERMANENT, c(552, Phase.DATA).kind());
    }

    @Test
    void unexpectedIntermediateReplyIsAProtocolError() {
        Classification r = c(354, Phase.RCPT);
        assertEquals(Kind.TRANSIENT, r.kind());
        assertEquals(DeliveryEngine.SMTP_PROTOCOL_ERROR, r.error());
    }

    @Test
    void networkAndDns() {
        assertEquals(Kind.TRANSIENT, ResultClassifier.network().kind());
        assertEquals(DeliveryEngine.CONNECTION_FAILED, ResultClassifier.network().error());
        Classification servfail = ResultClassifier.dns(
                new MxResolver.MxException(MxResolver.MxException.Kind.TEMPORARY, "SERVFAIL"));
        assertEquals(Kind.TRANSIENT, servfail.kind());
        assertEquals(DeliveryEngine.DNS_TEMPORARY_FAILURE, servfail.error());
        for (MxResolver.MxException.Kind k : new MxResolver.MxException.Kind[]{
                MxResolver.MxException.Kind.NO_SUCH_DOMAIN, MxResolver.MxException.Kind.NO_MAIL_HOST,
                MxResolver.MxException.Kind.NULL_MX}) {
            Classification r = ResultClassifier.dns(new MxResolver.MxException(k, "x"));
            assertEquals(Kind.PERMANENT, r.kind(), k.name());
            assertEquals(DeliveryEngine.NO_MAIL_HOST, r.error());
        }
    }
}
