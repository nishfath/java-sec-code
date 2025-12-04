package org.joychou.controller;

import org.apache.commons.codec.binary.Base64;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

@RestController
public class PathTraversal {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * http://localhost:8080/path_traversal/vul?filepath=../../../../../etc/passwd
     */
@GetMapping("/path_traversal/vul")
public String getImage(String filepath) throws IOException {
    return getImgBase64(filepath);
}


    @GetMapping("/path_traversal/sec")
    public String getImageSec(String filepath) throws IOException {
        if (SecurityUtil.pathFilter(filepath) == null) {
            logger.info("Illegal file path: " + filepath);
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }

private String getImgBase64(String imgFile) throws IOException {
    logger.info("Working directory: " + System.getProperty("user.dir"));
    logger.info("Requested file path: " + imgFile);
    
    // Define a secure base directory for all images
    String baseDir = System.getProperty("user.dir") + File.separator + "images";
    
    // Validate input
    if (imgFile == null || imgFile.isEmpty()) {
        return "Invalid file path provided";
    }
    
    // Remove any path traversal attempts
    String sanitizedPath = new File(baseDir, imgFile).getCanonicalPath();
    
    // Verify the sanitized path starts with the base directory to prevent directory traversal
    if (!sanitizedPath.startsWith(new File(baseDir).getCanonicalPath())) {
        logger.warn("Directory traversal attempt detected: " + imgFile);
        return "Access denied: Invalid path";
    }
    
    File f = new File(sanitizedPath);
    if (f.exists() && !f.isDirectory()) {
        byte[] data = Files.readAllBytes(Paths.get(sanitizedPath));
        return new String(Base64.encodeBase64(data));
    } else {
        return "File doesn't exist or is not a file.";
    }
}

    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}