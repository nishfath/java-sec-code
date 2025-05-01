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
        InputStream in = request.getInputStream();
        return convertStreamToString(in);
    }


    // https://stackoverflow.com/questions/309424/how-do-i-read-convert-an-inputstream-into-a-string-in-java
    public static String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
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
    
    // Don't create File object directly from user input
    // Instead, extract the extension safely using FilenameUtils
    try {
        URI uri = new URI(fullName);
        String path = uri.getPath();
        return FilenameUtils.getExtension(path);
    } catch (URISyntaxException e) {
        // If not a valid URI, try to extract extension safely
        return FilenameUtils.getExtension(fullName);
    }
}



public static String getNameWithoutExtension(String file) {
    Preconditions.checkNotNull(file);
    
    // Only use the last part of the path to avoid directory traversal
    String fileName = Paths.get(file).getFileName().toString();
    
    // Sanitize the filename to prevent directory traversal
    fileName = fileName.replaceAll("[/\\\\]", "");
    
    int dotIndex = fileName.lastIndexOf('.');
    return dotIndex == -1 ? fileName : fileName.substring(0, dotIndex);
}



}
