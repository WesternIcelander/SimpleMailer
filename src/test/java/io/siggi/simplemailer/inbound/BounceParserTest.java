package io.siggi.simplemailer.inbound;

import io.siggi.simplemailer.inbound.BounceParser.Kind;
import io.siggi.simplemailer.inbound.BounceParser.Recipient;
import io.siggi.simplemailer.inbound.BounceParser.Result;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BounceParserTest {
    private static final String VERP = "bounce+0b7c5a6e3f1d4c2a9e8b1a2b3c4d5e6f.0.0123456789abcdef@bounces.example.com";

    private static byte[] crlf(String s) {
        return s.replace("\r\n", "\n").replace("\n", "\r\n").getBytes(StandardCharsets.UTF_8);
    }

    private static final String POSTFIX = """
            Return-Path: <>
            Received: by mx.example.org (Postfix) id 3F1A2; Mon,  2 Nov 2026 10:00:01 +0000 (UTC)
            Date: Mon,  2 Nov 2026 10:00:01 +0000 (UTC)
            From: MAILER-DAEMON@mx.example.org (Mail Delivery System)
            Subject: Undelivered Mail Returned to Sender
            To: %s
            Auto-Submitted: auto-replied
            MIME-Version: 1.0
            Content-Type: multipart/report; report-type=delivery-status;
            	boundary="3F1A2.1730541601/mx.example.org"
            Message-Id: <20261102100001.3F1A2@mx.example.org>

            This is a MIME-encapsulated message.

            --3F1A2.1730541601/mx.example.org
            Content-Description: Notification
            Content-Type: text/plain; charset=us-ascii

            This is the mail system at host mx.example.org.

            I'm sorry to have to inform you that your message could not
            be delivered to one or more recipients.

            <nobody@example.org>: host mail.example.org[192.0.2.1] said: 550 5.1.1
                <nobody@example.org>: Recipient address rejected: User unknown (in reply
                to RCPT TO command)

            --3F1A2.1730541601/mx.example.org
            Content-Description: Delivery report
            Content-Type: message/delivery-status

            Reporting-MTA: dns; mx.example.org
            X-Postfix-Queue-ID: 3F1A2
            X-Postfix-Sender: rfc822; %s
            Arrival-Date: Mon,  2 Nov 2026 10:00:00 +0000 (UTC)

            Final-Recipient: rfc822; nobody@example.org
            Original-Recipient: rfc822;nobody@example.org
            Action: failed
            Status: 5.1.1
            Remote-MTA: dns; mail.example.org
            Diagnostic-Code: smtp; 550 5.1.1 <nobody@example.org>: Recipient address
                rejected: User unknown

            --3F1A2.1730541601/mx.example.org
            Content-Description: Undelivered Message Headers
            Content-Type: text/rfc822-headers

            From: sender@example.com
            To: nobody@example.org
            Subject: hello
            Message-ID: <0b7c5a6e-3f1d-4c2a-9e8b-1a2b3c4d5e6f@sender.example.com>

            --3F1A2.1730541601/mx.example.org--
            """.formatted(VERP, VERP);

    private static final String GMAIL = """
            Delivered-To: %s
            Return-Path: <>
            MIME-Version: 1.0
            From: Mail Delivery Subsystem <mailer-daemon@googlemail.com>
            To: %s
            Auto-Submitted: auto-replied
            Subject: Delivery Status Notification (Failure)
            References: <0b7c5a6e-3f1d-4c2a-9e8b-1a2b3c4d5e6f@sender.example.com>
            In-Reply-To: <0b7c5a6e-3f1d-4c2a-9e8b-1a2b3c4d5e6f@sender.example.com>
            X-Failed-Recipients: missing.person@gmail.com
            Message-ID: <6544a0f1.abc.gmr-mx@mx.google.com>
            Date: Mon, 02 Nov 2026 02:00:01 -0800 (PST)
            Content-Type: multipart/report; boundary="000000000000a1b2c3"; report-type=delivery-status

            --000000000000a1b2c3
            Content-Type: multipart/related; boundary="000000000000d4e5f6"

            --000000000000d4e5f6
            Content-Type: multipart/alternative; boundary="000000000000789abc"

            --000000000000789abc
            Content-Type: text/plain; charset="UTF-8"

            ** Address not found **

            Your message wasn't delivered to missing.person@gmail.com because the address couldn't be found.

            --000000000000789abc
            Content-Type: text/html; charset="UTF-8"

            <html><body><p>Address not found</p></body></html>

            --000000000000789abc--
            --000000000000d4e5f6--
            --000000000000a1b2c3
            Content-Type: message/delivery-status

            Reporting-MTA: dns; googlemail.com
            Received-From-MTA: dns; sender.example.com
            Arrival-Date: Mon, 02 Nov 2026 02:00:00 -0800 (PST)
            X-Original-Message-ID: <0b7c5a6e-3f1d-4c2a-9e8b-1a2b3c4d5e6f@sender.example.com>

            Final-Recipient: rfc822; missing.person@gmail.com
            Action: failed
            Status: 5.1.1
            Remote-MTA: dns; gmail-smtp-in.l.google.com. (2607:f8b0::1b, the server for
             the domain gmail.com.)
            Diagnostic-Code: smtp; 550-5.1.1 The email account that you tried to reach does
             not exist. Please try double-checking the recipient's email address for typos
             or unnecessary spaces. https://support.google.com/mail/?p=NoSuchUser
             a1si123456qkb.1 - gsmtp
            Last-Attempt-Date: Mon, 02 Nov 2026 02:00:01 -0800 (PST)

            --000000000000a1b2c3
            Content-Type: message/rfc822

            From: sender@example.com
            To: missing.person@gmail.com
            Subject: hello
            Message-ID: <0b7c5a6e-3f1d-4c2a-9e8b-1a2b3c4d5e6f@sender.example.com>

            Hello.

            --000000000000a1b2c3--
            """.formatted(VERP, VERP);

    private static final String OUTLOOK = """
            Return-Path: <>
            From: postmaster@outlook.com
            To: %s
            Date: Mon, 2 Nov 2026 10:00:02 +0000
            Content-Type: multipart/report; report-type=delivery-status;
            	boundary="aa0b1c2d-3e4f-5a6b-7c8d-9e0f1a2b3c4d"
            X-MS-Exchange-Message-Is-Ndr:
            Content-Language: en-US
            Message-ID: <aa0b1c2d-3e4f-5a6b-7c8d-9e0f1a2b3c4d@DM6PR01MB1234.namprd01.prod.outlook.com>
            Subject: Undeliverable: hello
            Auto-Submitted: auto-replied
            MIME-Version: 1.0

            --aa0b1c2d-3e4f-5a6b-7c8d-9e0f1a2b3c4d
            Content-Type: multipart/alternative; differences=Content-Type;
            	boundary="bb0b1c2d-3e4f-5a6b-7c8d-9e0f1a2b3c4d"

            --bb0b1c2d-3e4f-5a6b-7c8d-9e0f1a2b3c4d
            Content-Type: text/plain; charset="us-ascii"
            Content-Transfer-Encoding: quoted-printable

            Your message to gone@contoso.com couldn't be delivered.=0D
            gone wasn't found at contoso.com.=0D

            --bb0b1c2d-3e4f-5a6b-7c8d-9e0f1a2b3c4d--

            --aa0b1c2d-3e4f-5a6b-7c8d-9e0f1a2b3c4d
            Content-Type: message/delivery-status
            Content-Transfer-Encoding: base64

            %s
            --aa0b1c2d-3e4f-5a6b-7c8d-9e0f1a2b3c4d
            Content-Type: message/rfc822

            Message-ID: <0b7c5a6e-3f1d-4c2a-9e8b-1a2b3c4d5e6f@sender.example.com>
            Subject: hello

            --aa0b1c2d-3e4f-5a6b-7c8d-9e0f1a2b3c4d--
            """.formatted(VERP, Base64.getMimeEncoder().encodeToString(crlf("""
            Reporting-MTA: dns;DM6PR01MB1234.namprd01.prod.outlook.com
            Received-From-MTA: dns;sender.example.com
            Arrival-Date: Mon, 2 Nov 2026 10:00:01 +0000

            Final-Recipient: rfc822;gone@contoso.com
            Action: failed
            Status: 5.1.10
            Diagnostic-Code: smtp;550 5.1.10 RESOLVER.ADR.RecipientNotFound; Recipient gone@contoso.com not found by SMTP address lookup
            """)));

    @Test
    void parsesPostfixDsn() {
        Result r = BounceParser.parse(crlf(POSTFIX), "<>");
        assertEquals(Kind.DSN, r.kind());
        assertTrue(r.isBounce());
        assertEquals("mx.example.org", r.reportingMta());
        assertEquals("<20261102100001.3F1A2@mx.example.org>", r.messageId());
        assertEquals("<0b7c5a6e-3f1d-4c2a-9e8b-1a2b3c4d5e6f@sender.example.com>", r.originalMessageId());
        assertEquals("Undelivered Mail Returned to Sender", r.subject());
        assertEquals(1, r.recipients().size());
        Recipient rcpt = r.recipients().get(0);
        assertEquals("nobody@example.org", rcpt.finalRecipient());
        assertEquals("nobody@example.org", rcpt.originalRecipient());
        assertEquals("failed", rcpt.action());
        assertTrue(rcpt.failed());
        assertEquals("5.1.1", rcpt.status());
        assertEquals("550 5.1.1 <nobody@example.org>: Recipient address rejected: User unknown",
                rcpt.diagnosticCode());
        assertEquals("mail.example.org", rcpt.remoteMta());
    }

    @Test
    void parsesGmailDsnWithNestedNotification() {
        Result r = BounceParser.parse(crlf(GMAIL), null);
        assertEquals(Kind.DSN, r.kind());
        assertEquals("googlemail.com", r.reportingMta());
        assertEquals("<0b7c5a6e-3f1d-4c2a-9e8b-1a2b3c4d5e6f@sender.example.com>", r.originalMessageId());
        Recipient rcpt = r.recipients().get(0);
        assertEquals("missing.person@gmail.com", rcpt.finalRecipient());
        assertNull(rcpt.originalRecipient());
        assertEquals("5.1.1", rcpt.status());
        assertTrue(rcpt.diagnosticCode().startsWith("550-5.1.1 The email account that you tried to reach does not exist."),
                rcpt.diagnosticCode());
        assertTrue(rcpt.diagnosticCode().endsWith("a1si123456qkb.1 - gsmtp"), rcpt.diagnosticCode());
    }

    @Test
    void parsesOutlookDsnWithBase64DeliveryStatus() {
        Result r = BounceParser.parse(crlf(OUTLOOK), "");
        assertEquals(Kind.DSN, r.kind());
        assertEquals("DM6PR01MB1234.namprd01.prod.outlook.com", r.reportingMta());
        Recipient rcpt = r.recipients().get(0);
        assertEquals("gone@contoso.com", rcpt.finalRecipient());
        assertEquals("5.1.10", rcpt.status());
        assertTrue(rcpt.diagnosticCode().startsWith("550 5.1.10 RESOLVER.ADR.RecipientNotFound"));
    }

    @Test
    void acceptsBareLfLineEndingsAndMboxFromLine() {
        byte[] lf = ("From MAILER-DAEMON  Mon Nov  2 10:00:01 2026\n" + POSTFIX).getBytes(StandardCharsets.UTF_8);
        Result r = BounceParser.parse(lf, null);
        assertEquals(Kind.DSN, r.kind());
        assertEquals("nobody@example.org", r.recipients().get(0).finalRecipient());
        assertEquals("5.1.1", r.recipients().get(0).status());
    }

    @Test
    void delayedDsnReportsDelayedAction() {
        String dsn = """
                From: MAILER-DAEMON@mx.example.org
                Subject: Delayed Mail (still being retried)
                Content-Type: multipart/report; report-type=delivery-status; boundary=BND

                --BND
                Content-Type: text/plain

                Still trying.
                --BND
                Content-Type: message/delivery-status

                Reporting-MTA: dns; mx.example.org


                Final-Recipient: rfc822; <slow@example.org>
                Action: delayed (will retry)
                Status: 4.4.1 (connection timed out)
                Diagnostic-Code: X-Postfix; connect to mail.example.org: Connection timed out
                --BND--
                """;
        Result r = BounceParser.parse(crlf(dsn), "<>");
        assertEquals(Kind.DSN, r.kind());
        Recipient rcpt = r.recipients().get(0);
        assertEquals("slow@example.org", rcpt.finalRecipient());
        assertEquals("delayed", rcpt.action());
        assertTrue(rcpt.delayed());
        assertFalse(rcpt.failed());
        assertEquals("4.4.1", rcpt.status());
        assertEquals("connect to mail.example.org: Connection timed out", rcpt.diagnosticCode());
    }

    @Test
    void multipleRecipientGroups() {
        String dsn = """
                Content-Type: multipart/report; report-type=delivery-status; boundary="b+1"

                --b+1
                Content-Type: message/delivery-status

                Reporting-MTA: dns; mx.example.org

                Final-Recipient: rfc822; a@example.org
                Action: failed
                Status: 5.2.2

                Final-Recipient: rfc822; b@example.org
                Action: delivered
                Status: 2.0.0
                --b+1--
                """;
        Result r = BounceParser.parse(crlf(dsn), "<>");
        assertEquals(Kind.DSN, r.kind());
        assertEquals(2, r.recipients().size());
        assertEquals("a@example.org", r.recipients().get(0).finalRecipient());
        assertEquals("5.2.2", r.recipients().get(0).status());
        assertEquals("delivered", r.recipients().get(1).action());
    }

    @Test
    void nonDsnBounceWithNullSenderIsFailure() {
        String qmail = """
                From: MAILER-DAEMON@mail.example.net
                To: %s
                Subject: failure notice

                Hi. This is the qmail-send program at mail.example.net.
                I'm afraid I wasn't able to deliver your message to the following addresses.

                <nobody@example.net>:
                192.0.2.7 does not like recipient.
                Remote host said: 550 5.1.1 <nobody@example.net>... User unknown
                Giving up on 192.0.2.7.
                """.formatted(VERP);
        Result r = BounceParser.parse(crlf(qmail), "<>");
        assertEquals(Kind.NON_DSN_BOUNCE, r.kind());
        assertTrue(r.isBounce());
        assertEquals(1, r.recipients().size());
        Recipient rcpt = r.recipients().get(0);
        assertNull(rcpt.finalRecipient());
        assertTrue(rcpt.failed());
        assertEquals("5.1.1", rcpt.status());
        assertEquals("550 5.1.1 <nobody@example.net>... User unknown", rcpt.diagnosticCode());
    }

    @Test
    void nonDsnBounceDetectedFromReturnPathWhenEnvelopeUnknown() {
        String msg = """
                Return-Path: <>
                From: Postmaster <postmaster@example.net>
                Subject: Message not delivered

                Sorry, the mailbox is full.
                """;
        Result r = BounceParser.parse(crlf(msg), null);
        assertEquals(Kind.NON_DSN_BOUNCE, r.kind());
        assertNull(r.recipients().get(0).status());
        assertEquals("Message not delivered", r.recipients().get(0).diagnosticCode());
    }

    @Test
    void autoReplyIsIgnoredEvenWithNullSender() {
        String vacation = """
                Return-Path: <>
                From: Alice <alice@example.org>
                To: %s
                Subject: Out of office: hello
                Auto-Submitted: auto-replied (vacation)
                Message-ID: <vac1@example.org>

                I'm away until Monday.
                """.formatted(VERP);
        Result r = BounceParser.parse(crlf(vacation), "<>");
        assertEquals(Kind.AUTO_REPLY, r.kind());
        assertFalse(r.isBounce());
        assertTrue(r.recipients().isEmpty());
        assertEquals("<vac1@example.org>", r.messageId());

        String xAuto = """
                From: bob@example.org
                X-Autoreply: yes
                Subject: Re: hello

                Thanks!
                """;
        assertEquals(Kind.AUTO_REPLY, BounceParser.parse(crlf(xAuto), "bob@example.org").kind());
    }

    @Test
    void ordinaryReplyIsNotABounce() {
        String reply = """
                Return-Path: <bob@example.org>
                From: Bob <bob@example.org>
                Subject: Re: hello

                Got it, 550 5.1.1 is not a bounce when a human writes it.
                """;
        assertEquals(Kind.NOT_BOUNCE, BounceParser.parse(crlf(reply), "bob@example.org").kind());
        // the envelope sender wins over the Return-Path header when known
        String spoofed = reply.replace("Return-Path: <bob@example.org>", "Return-Path: <>");
        assertEquals(Kind.NOT_BOUNCE, BounceParser.parse(crlf(spoofed), "bob@example.org").kind());
    }

    @Test
    void reportWithoutRecipientsFallsBackToHeuristics() {
        String odd = """
                From: someone@example.org
                Content-Type: multipart/report; report-type=delivery-status; boundary=X

                --X
                Content-Type: message/delivery-status

                Reporting-MTA: dns; mx.example.org
                --X--
                """;
        assertEquals(Kind.NON_DSN_BOUNCE, BounceParser.parse(crlf(odd), "<>").kind());
        assertEquals(Kind.NOT_BOUNCE, BounceParser.parse(crlf(odd), "someone@example.org").kind());
    }

    @Test
    void malformedInputNeverThrows() {
        assertEquals(Kind.NOT_BOUNCE, BounceParser.parse(new byte[0], null).kind());
        assertEquals(Kind.NOT_BOUNCE, BounceParser.parse(crlf("no colon here\n\nbody"), null).kind());
        String truncated = POSTFIX.substring(0, POSTFIX.indexOf("Action: failed"));
        Result r = BounceParser.parse(crlf(truncated), "<>");
        assertEquals(Kind.DSN, r.kind());
        assertEquals("nobody@example.org", r.recipients().get(0).finalRecipient());
        String noBoundary = "Content-Type: multipart/report; report-type=delivery-status\r\n\r\nx\r\n";
        assertEquals(Kind.NON_DSN_BOUNCE, BounceParser.parse(noBoundary.getBytes(StandardCharsets.US_ASCII), "").kind());
    }

    @Test
    void contentHashIsSha256OfRawBytes() throws Exception {
        byte[] raw = crlf(POSTFIX);
        String expected = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
        assertEquals(expected, BounceParser.parse(raw, "<>").contentHash());
    }

    @Test
    void quotedPrintableAndLineEndingHelpers() {
        assertArrayEquals("a=b\r\nc".getBytes(StandardCharsets.US_ASCII),
                BounceParser.decodeQuotedPrintable("a=3Db\r\nc".getBytes(StandardCharsets.US_ASCII)));
        assertArrayEquals("abc".getBytes(StandardCharsets.US_ASCII),
                BounceParser.decodeQuotedPrintable("ab=\r\nc".getBytes(StandardCharsets.US_ASCII)));
        assertArrayEquals("a\r\nb\r\nc\r\n".getBytes(StandardCharsets.US_ASCII),
                BounceParser.toCrlf("a\nb\r\nc\r".getBytes(StandardCharsets.US_ASCII)));
    }
}
