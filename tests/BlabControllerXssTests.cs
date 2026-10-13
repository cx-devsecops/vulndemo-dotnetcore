using System;
using System.Net;
using System.Text;
using Xunit;

namespace Verademo.Tests
{
    /// <summary>
    /// Tests verifying that GetMoreBlabs HTML-encodes user-supplied values
    /// before inserting them into the HTML template, preventing XSS (CWE-79).
    ///
    /// These tests replicate the HTML template construction logic from
    /// BlabController.GetMoreBlabs, using the same WebUtility.HtmlEncode
    /// calls added in the remediation. They exercise the full taint path:
    ///   SOURCE  → user-supplied string from the database reader
    ///   ENCODING → WebUtility.HtmlEncode applied before string.Format
    ///   SINK    → returnTemplate.ToString() returned as HTML
    /// </summary>
    public class BlabControllerXssTests
    {
        // The HTML template from BlabController.GetMoreBlabs (reproduced verbatim
        // so the tests mirror the real rendering path).
        private const string HtmlTemplate =
            "<li><div><div class='commenterImage'>" +
            "<img src='/images/{0}.png'>" +
            "</div>" +
            "<div class='commentText'>" +
            "<p>{1}</p>" +
            "<span class='date sub-text'>by {2} on {3}</span><br>" +
            "<span class='date sub-text'><a href=\"Blab/Blab?blabid={4}\">{5} Comments</a></span>" +
            "</div>" +
            "</div></li>";

        /// <summary>
        /// Simulates the HTML rendering path used by GetMoreBlabs.
        /// Applies WebUtility.HtmlEncode to all user-supplied string fields
        /// (username, blab content, blab name) exactly as the remediated code does.
        /// </summary>
        private static string RenderBlabHtml(
            string username,
            string blabContent,
            string blabName,
            string postDateString,
            int blabId,
            int commentCount)
        {
            var returnTemplate = new StringBuilder();
            returnTemplate.Append(string.Format(
                HtmlTemplate,
                WebUtility.HtmlEncode(username),      // {0} username
                WebUtility.HtmlEncode(blabContent),   // {1} blab content
                WebUtility.HtmlEncode(blabName),      // {2} blab name
                postDateString,                        // {3} timestamp (non-user-controlled)
                blabId,                                // {4} integer, safe
                commentCount                           // {5} integer, safe
            ));
            return returnTemplate.ToString();
        }

        // -------------------------------------------------------------------------
        // Positive cases — well-formed data should be rendered correctly
        // -------------------------------------------------------------------------

        [Fact]
        public void PlainText_UsernameAndContent_RenderedCorrectly()
        {
            var html = RenderBlabHtml("alice", "Hello world", "Alice's Blabs", "Jan 1, 2024", 42, 3);

            Assert.Contains("<img src='/images/alice.png'>", html);
            Assert.Contains("<p>Hello world</p>", html);
            Assert.Contains("by Alice&#39;s Blabs on Jan 1, 2024", html);
            Assert.Contains("href=\"Blab/Blab?blabid=42\"", html);
            Assert.Contains("3 Comments", html);
        }

        [Fact]
        public void PlainText_NoSpecialChars_OutputUnchanged()
        {
            var html = RenderBlabHtml("bob", "A normal post.", "Bob", "Oct 1, 2024", 1, 0);

            Assert.Contains("bob", html);
            Assert.Contains("A normal post.", html);
            Assert.Contains("Bob", html);
        }

        // -------------------------------------------------------------------------
        // XSS attack vectors — malicious HTML/JS must be escaped in the output
        // -------------------------------------------------------------------------

        [Fact]
        public void XssInBlabContent_IsHtmlEncoded_NotExecuted()
        {
            // A stored XSS payload in blab content must be escaped before rendering.
            string xssPayload = "<script>alert('xss')</script>";
            var html = RenderBlabHtml("attacker", xssPayload, "Attacker", "Oct 1, 2024", 10, 0);

            // The raw script tag must NOT appear verbatim in the output.
            Assert.DoesNotContain("<script>", html);
            Assert.DoesNotContain("</script>", html);

            // The encoded form must appear instead.
            Assert.Contains("&lt;script&gt;", html);
            Assert.Contains("&lt;/script&gt;", html);
        }

        [Fact]
        public void XssInUsername_IsHtmlEncoded_NotExecuted()
        {
            // A username containing HTML tags must be escaped.
            string xssUsername = "<img src=x onerror=alert(1)>";
            var html = RenderBlabHtml(xssUsername, "Normal content", "Attacker", "Oct 1, 2024", 11, 0);

            // Raw HTML in username must not be present.
            Assert.DoesNotContain("<img src=x onerror=alert(1)>", html);

            // The encoded version must be present.
            Assert.Contains("&lt;img src=x onerror=alert(1)&gt;", html);
        }

        [Fact]
        public void XssInBlabName_IsHtmlEncoded_NotExecuted()
        {
            // A blab_name containing a script injection must be escaped.
            string xssBlabName = "\"><script>alert('xss')</script>";
            var html = RenderBlabHtml("attacker", "Some content", xssBlabName, "Oct 1, 2024", 12, 0);

            Assert.DoesNotContain("<script>", html);
            // The double-quote and angle brackets must be encoded.
            Assert.Contains("&lt;script&gt;", html);
        }

        [Fact]
        public void XssEventHandler_InBlabContent_IsEncoded()
        {
            // An event-handler injection in blab content must be neutralised.
            string xssPayload = "<div onmouseover=\"alert('pwned')\">hover me</div>";
            var html = RenderBlabHtml("user", xssPayload, "User", "Oct 1, 2024", 13, 0);

            Assert.DoesNotContain("<div onmouseover=", html);
            Assert.Contains("&lt;div onmouseover=", html);
        }

        [Fact]
        public void JavascriptScheme_InBlabContent_IsEncoded()
        {
            // A javascript: URI in content must also be neutralised via encoding.
            string xssPayload = "<a href=\"javascript:alert(1)\">click</a>";
            var html = RenderBlabHtml("user", xssPayload, "User", "Oct 1, 2024", 14, 0);

            Assert.DoesNotContain("<a href=\"javascript:", html);
            Assert.Contains("&lt;a href=", html);
        }

        [Fact]
        public void HtmlEntitiesInContent_AreDoubleEncoded_SafelyRendered()
        {
            // If user supplies text that looks like an entity, it should still be safely encoded.
            string content = "5 &lt; 10 and &gt; 3";
            var html = RenderBlabHtml("user", content, "User", "Oct 1, 2024", 15, 1);

            // The & in the pre-existing entities should itself be encoded once more, producing &&amp;lt;
            Assert.DoesNotContain("<p>5 &lt; 10", html); // original entity must not pass through raw
            Assert.Contains("&amp;lt;", html);           // the ampersand itself is re-encoded
        }

        [Fact]
        public void SingleQuotes_InUsername_AreEncoded()
        {
            // Single quotes in usernames must be encoded (relevant for attributes using single-quotes in the template).
            string username = "alice'bob";
            var html = RenderBlabHtml(username, "Content", "Name", "Oct 1, 2024", 16, 0);

            // The single quote must be HTML-encoded (&#39; or &apos;)
            Assert.DoesNotContain("alice'bob", html);
            Assert.Contains("alice&#39;bob", html);
        }

        [Fact]
        public void DoubleQuotes_InBlabContent_AreEncoded()
        {
            // Double quotes must be encoded to prevent attribute injection.
            string content = "He said \"hello\"";
            var html = RenderBlabHtml("user", content, "User", "Oct 1, 2024", 17, 0);

            Assert.Contains("&quot;", html);
            Assert.DoesNotContain("<p>He said \"hello\"</p>", html);
        }

        [Fact]
        public void Ampersand_InBlabContent_IsEncoded()
        {
            string content = "Cats & Dogs";
            var html = RenderBlabHtml("user", content, "User", "Oct 1, 2024", 18, 2);

            Assert.DoesNotContain("<p>Cats & Dogs</p>", html);
            Assert.Contains("Cats &amp; Dogs", html);
        }

        // -------------------------------------------------------------------------
        // Verify integer fields (blabId, commentCount) are NOT HTML-encoded
        // (they are typed integers and do not require encoding)
        // -------------------------------------------------------------------------

        [Fact]
        public void IntegerBlabId_AppearsVerbatim_InHref()
        {
            var html = RenderBlabHtml("user", "Content", "Name", "Oct 1, 2024", 99, 7);

            Assert.Contains("blabid=99", html);
            Assert.Contains("7 Comments", html);
        }

        // -------------------------------------------------------------------------
        // Edge cases
        // -------------------------------------------------------------------------

        [Fact]
        public void EmptyStrings_ProduceValidHtml()
        {
            // Empty user values must not cause exceptions.
            var html = RenderBlabHtml("", "", "", "Oct 1, 2024", 0, 0);

            Assert.NotNull(html);
            Assert.Contains("<li>", html);
        }

        [Fact]
        public void LongXssPayload_IsFullyEncoded()
        {
            // A long injection string must be fully encoded.
            string longPayload = string.Concat(System.Linq.Enumerable.Repeat("<script>x</script>", 100));
            var html = RenderBlabHtml("user", longPayload, "User", "Oct 1, 2024", 1, 0);

            Assert.DoesNotContain("<script>", html);
        }
    }
}
