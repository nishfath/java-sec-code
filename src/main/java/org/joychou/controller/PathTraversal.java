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
    // Initial security check using existing pathFilter
    if (SecurityUtil.pathFilter(filepath) == null) {
        logger.info("Illegal file path: " + filepath);
        return "Bad boy. Illegal file path.";
    }
    
    // Additional security - define a base directory for allowed files
    String baseDir = System.getProperty("user.dir") + File.separator + "images";
    
    try {
        return getImgBase64(baseDir, filepath);
    } catch (SecurityException e) {
        logger.error("Security violation: " + e.getMessage());
        return "Security violation detected.";
    }
}

        return getImgBase64(filepath);
    }

private String getImgBase64(String baseDir, String relativeFilePath) throws IOException {
    // Create base directory if it doesn't exist
    File baseDirFile = new File(baseDir);
    if (!baseDirFile.exists()) {
        baseDirFile.mkdirs();
    }
    
    // Normalize paths for security comparison
    Path basePath = baseDirFile.toPath().normalize().toAbsolutePath();
    Path filePath = new File(baseDir, relativeFilePath).toPath().normalize().toAbsolutePath();
    
    // Check if the resolved file path is within the base directory
    if (!filePath.startsWith(basePath)) {
        logger.warn("Directory traversal attempt: " + relativeFilePath);
        throw new SecurityException("Access to the specified file path is restricted");
    }
    
    logger.info("Working directory: " + System.getProperty("user.dir"));
    logger.info("File path: " + filePath);
    
    File f = filePath.toFile();
    if (f.exists() && !f.isDirectory()) {
        byte[] data = Files.readAllBytes(filePath);
        return new String(Base64.encodeBase64(data));
    } else {
        return "File doesn't exist or is not a file.";
    }
}


    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}