package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.joychou.security.ssrf.SSRFException;
import org.joychou.util.HttpUtils;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.*;


/**
 * Java SSRF vuln or security code.
 *
 * @author JoyChou @2017-12-28
 */

@RestController
@RequestMapping("/ssrf")
public class SSRF {

    private static Logger logger = LoggerFactory.getLogger(SSRF.class);


    /**
     * The default setting of followRedirects is true.
     * UserAgent is Java/1.8.0_102.
     */
    @GetMapping("/HttpURLConnection/sec")
    public String httpURLConnection(@RequestParam String url) {
        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.HttpURLConnection(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }
    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Apache-HttpClient/4.5.12 (Java/1.8.0_102)</code>.
     *
     * http://localhost:8080/ssrf/request/sec?url=http://test.joychou.org
     */
    @GetMapping("/request/sec")
    public String request(@RequestParam String url) {
        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.request(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }
    }


    /**
     * Download the url file.
     * http://localhost:8080/ssrf/openStream?url=file:///etc/passwd
     * <p>
     * new URL(String url).openConnection()
     * new URL(String url).openStream()
     * new URL(String url).getContent()
     */
@GetMapping("/openStream")
public void openStream(@RequestParam String url, HttpServletResponse response) throws IOException {
    InputStream inputStream = null;
    OutputStream outputStream = null;
    try {
        // Validate URL to prevent SSRF
        UrlValidator urlValidator = new UrlValidator(new String[]{"http", "https"});
        if (!urlValidator.isValid(url)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Invalid URL provided");
            return;
        }
        
        // Validate URL host to prevent accessing internal resources
        URL u = new URL(url);
        String host = u.getHost();
        // Block access to private networks and localhost
        if (isPrivateAddress(host)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("Access to internal resources is not allowed");
            return;
        }

        // Sanitize and get filename
        String downLoadImgFileName = WebUtils.getNameWithoutExtension(url) + "." + WebUtils.getFileExtension(url);
        
        // Set content-disposition header with proper filename encoding
        response.setHeader("content-disposition", "attachment;fileName=" + 
                           java.net.URLEncoder.encode(downLoadImgFileName, "UTF-8"));

        int length;
        byte[] bytes = new byte[1024];
        inputStream = u.openStream(); // send request
        outputStream = response.getOutputStream();
        while ((length = inputStream.read(bytes)) > 0) {
            outputStream.write(bytes, 0, length);
        }

    } catch (Exception e) {
        logger.error(e.toString());
        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } finally {
        if (inputStream != null) {
            inputStream.close();
        }
        if (outputStream != null) {
            outputStream.close();
        }
    }
}

// Helper method to check if an address is private
private boolean isPrivateAddress(String host) {
    if (host.equalsIgnoreCase("localhost") || host.equals("127.0.0.1") || host.startsWith("192.168.") ||
        host.startsWith("10.") || host.matches("172\\.(1[6-9]|2[0-9]|3[0-1])\\..*")) {
        return true;
    }
    return false;
}


    } catch (Exception e) {
        logger.error(e.toString());
    } finally {
        if (inputStream != null) {
            inputStream.close();
        }
        if (outputStream != null) {
            outputStream.close();
        }
    }
}

        }
    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is Java/1.8.0_102.
     */
    @GetMapping("/ImageIO/sec")
    public String ImageIO(@RequestParam String url) {
        try {
            SecurityUtil.startSSRFHook();
            HttpUtils.imageIO(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

        return "ImageIO ssrf test";
    }


    @GetMapping("/okhttp/sec")
    public String okhttp(@RequestParam String url) {

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.okhttp(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Apache-HttpClient/4.5.12 (Java/1.8.0_102)</code>.
     *
     * http://localhost:8080/ssrf/httpclient/sec?url=http://www.baidu.com
     */
    @GetMapping("/httpclient/sec")
    public String HttpClient(@RequestParam String url) {

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.httpClient(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Jakarta Commons-HttpClient/3.1</code>.
     *
     * http://localhost:8080/ssrf/commonsHttpClient/sec?url=http://www.baidu.com
     */
    @GetMapping("/commonsHttpClient/sec")
    public String commonsHttpClient(@RequestParam String url) {

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.commonHttpClient(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }

    /**
     * The default setting of followRedirects is true.
     * UserAgent is the useragent of browser.
     *
     * http://localhost:8080/ssrf/Jsoup?url=http://www.baidu.com
     */
    @GetMapping("/Jsoup/sec")
    public String Jsoup(@RequestParam String url) {

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.Jsoup(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Java/1.8.0_102</code>.
     *
     * http://localhost:8080/ssrf/IOUtils/sec?url=http://www.baidu.com
     */
    @GetMapping("/IOUtils/sec")
    public String IOUtils(String url) {
        try {
            SecurityUtil.startSSRFHook();
            HttpUtils.IOUtils(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

        return "IOUtils ssrf test";
    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Apache-HttpAsyncClient/4.1.4 (Java/1.8.0_102)</code>.
     */
    @GetMapping("/HttpSyncClients/vuln")
    public String HttpSyncClients(@RequestParam("url") String url) {
        return HttpUtils.HttpAsyncClients(url);
    }


}
