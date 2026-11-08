package io.siggi.simplemailer.mime;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HeaderParamsTest {
    @Test
    void parsesValueAndTokenParams() {
        HeaderParams p = HeaderParams.parse("multipart/report; report-type=delivery-status; boundary=abc123");
        assertEquals("multipart/report", p.value());
        assertEquals("delivery-status", p.get("report-type"));
        assertEquals("abc123", p.get("boundary"));
    }

    @Test
    void doesNotUrlDecode() {
        HeaderParams p = HeaderParams.parse("multipart/mixed; boundary=a+b%zz");
        assertEquals("a+b%zz", p.get("boundary"));
        assertEquals("a+b%2F", HeaderParams.parse("multipart/mixed; boundary=\"a+b%2F\"").get("boundary"));
    }

    @Test
    void quotedStringsWithEscapesAndSpecials() {
        HeaderParams p = HeaderParams.parse("text/plain; name=\"we\\\"ird; name=x.txt\"; charset=utf-8");
        assertEquals("we\"ird; name=x.txt", p.get("name"));
        assertEquals("utf-8", p.get("charset"));
    }

    @Test
    void namesAreCaseInsensitiveAndValueKeepsCase() {
        HeaderParams p = HeaderParams.parse("Text/HTML; CharSet=UTF-8");
        assertEquals("Text/HTML", p.value());
        assertEquals("text/html", p.lowerValue());
        assertEquals("UTF-8", p.get("charset"));
        assertEquals("UTF-8", p.get("CHARSET"));
    }

    @Test
    void foldedWhitespaceAndComments() {
        HeaderParams p = HeaderParams.parse("multipart/mixed (a comment; x=y);\r\n\tboundary=\"b1\" (trailing)\r\n ; charset = us-ascii");
        assertEquals("multipart/mixed", p.value());
        assertEquals("b1", p.get("boundary"));
        assertEquals("us-ascii", p.get("charset"));
        assertNull(p.get("x"));
    }

    @Test
    void firstOccurrenceWins() {
        assertEquals("1", HeaderParams.parse("a/b; x=1; X=2").get("x"));
    }

    @Test
    void rfc2231ExtendedAndContinuations() {
        assertEquals("Grüße.txt", HeaderParams.parse("attachment; filename*=UTF-8''Gr%C3%BC%C3%9Fe.txt").get("filename"));
        assertEquals("long name here.pdf", HeaderParams.parse(
                "attachment; filename*0=\"long \"; filename*1=\"name \"; filename*2=here.pdf").get("filename"));
        // Mixed extended / plain continuations, with a multi-byte character split across segments.
        assertEquals("€uro rate.txt", HeaderParams.parse(
                "attachment; filename*0*=utf-8'en'%E2%82; filename*1*=%ACuro; filename*2=\" rate.txt\"").get("filename"));
        // Extended form overrides the plain fallback.
        assertEquals("ü.txt", HeaderParams.parse(
                "attachment; filename=\"u.txt\"; filename*=utf-8''%C3%BC.txt").get("filename"));
        // A gap stops the continuation.
        assertEquals("ab", HeaderParams.parse("a/b; n*0=a; n*1=b; n*3=d").get("n"));
    }

    @Test
    void lenientOnGarbage() {
        HeaderParams p = HeaderParams.parse(";;; =x; novalue; y=\"unterminated");
        assertEquals("", p.value());
        assertEquals("unterminated", p.get("y"));
        assertNull(p.get("novalue"));
        assertEquals("", HeaderParams.parse(null).value());
        assertTrue(HeaderParams.parse("text/plain").params().isEmpty());
    }

    @Test
    void quoteAndFormat() {
        assertTrue(HeaderParams.isToken("abc-1.2"));
        assertFalse(HeaderParams.isToken("a b"));
        assertFalse(HeaderParams.isToken(""));
        assertEquals("abc", HeaderParams.quote("abc"));
        assertEquals("\"a b\"", HeaderParams.quote("a b"));
        assertEquals("\"a\\\"b\\\\c\"", HeaderParams.quote("a\"b\\c"));
        assertEquals("\"ab\"", HeaderParams.quote("a\r\nb").replace(" ", ""));

        Map<String, String> params = new LinkedHashMap<>();
        params.put("charset", "utf-8");
        params.put("name", "my file.txt");
        String formatted = HeaderParams.format("text/plain", params);
        assertEquals("text/plain; charset=utf-8; name=\"my file.txt\"", formatted);
        HeaderParams back = HeaderParams.parse(formatted);
        assertEquals("my file.txt", back.get("name"));
        assertEquals("utf-8", back.get("charset"));
    }
}
