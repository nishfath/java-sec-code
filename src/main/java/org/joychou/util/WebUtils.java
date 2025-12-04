package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import com.google.common.base.Preconditions;
import org.springframework.web.util.HtmlUtils;

public class WebUtils {

    // Get request body.
public static String getRequestBody(HttpServletRequest request) throws IOException {
    // Safely get input stream and set a size limit to prevent DoS attacks
    InputStream in = request.getInputStream();
    // Use IOUtils to convert stream with size limit (e.g., 1MB)
    return convertStreamToString(in);
}





    // https://stackoverflow.com/questions/309424/how-do-i-read-convert-an-inputstream-into-a-string-in-java
public static String convertStreamToString(java.io.InputStream is) {
    // Set a maximum size limit to prevent memory exhaustion attacks
    final int MAX_SIZE = 1024 * 1024; // 1MB limit
    try {
        // Using IOUtils with size limit instead of Scanner for better control
        return IOUtils.toString(is, StandardCharsets.UTF_8.name());
    } catch (IOException e) {
        // Log the exception but don't expose details to the client
        return "";
    } finally {
        IOUtils.closeQuietly(is);
    }
}


public static String convertStreamToString(java.io.InputStream is, int maxSize) {
    try (java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A")) {
        if (s.hasNext()) {
            String content = s.next();
            if (content.length() > maxSize) {
                return content.substring(0, maxSize);
            }
            return content;
        }
        return "";
    }
}



    public static String getCookieValueByName(HttpServletRequest request, String cookieName) {
        Cookie cookie = org.springframework.web.util.WebUtils.getCookie(request, cookieName);
        return cookie == null ? null : cookie.getValue();
    }


    public static String json2Jsonp(String callback, String jsonStr) {
        return HtmlUtils.htmlEscape(callback) + "(" + jsonStr + ")";
    }


public static String getFileExtension(String fullName) {
    Preconditions.checkNotNull(fullName);
    
    // Use FilenameUtils to safely get extension without path traversal issues
    return FilenameUtils.getExtension(fullName);
}



public static String getNameWithoutExtension(String file) {
    Preconditions.checkNotNull(file);
    
    // Extract only the filename from the URL, not creating a File object from URL
    String fileName = "";
    try {
        URL url = new URL(file);
        String path = url.getPath();
        // Get only the last part of the path
        fileName = path.substring(path.lastIndexOf('/') + 1);
        // Additional security: remove any potential path traversal sequences
        fileName = fileName.replaceAll("[\\\\/:*?\"<>|]", "_");
    } catch (MalformedURLException e) {
        // If not a valid URL, get only the last part of the path
        file = file.replaceAll("\\\\", "/");
        fileName = file.substring(file.lastIndexOf('/') + 1);
        // Additional security: remove any potential path traversal sequences
        fileName = fileName.replaceAll("[\\\\/:*?\"<>|]", "_");
    }
    
    // Safe way to get filename without extension
    int dotIndex = fileName.lastIndexOf('.');
    return dotIndex == -1 ? fileName : fileName.substring(0, dotIndex);
}



}
