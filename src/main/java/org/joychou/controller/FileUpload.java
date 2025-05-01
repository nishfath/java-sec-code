package org.joychou.controller;

import com.fasterxml.uuid.Generators;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import org.joychou.security.SecurityUtil;


/**
 * File upload.
 *
 * @author JoyChou @ 2018-08-15
 */
@Controller
@RequestMapping("/file")
public class FileUpload {

    // Save the uploaded file to this folder
    private static final String UPLOADED_FOLDER = "/tmp/";
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private static String randomFilePath = "";

    // uplaod any file
    @GetMapping("/any")
    public String index() {
        return "upload"; // return upload.html page
    }

    // only allow to upload pictures
    @GetMapping("/pic")
    public String uploadPic() {
        return "uploadPic"; // return uploadPic.html page
    }

@PostMapping("/upload")
public String singleFileUpload(@RequestParam("file") MultipartFile file,
                               RedirectAttributes redirectAttributes) {
    if (file.isEmpty()) {
        // 赋值给uploadStatus.html里的动态参数message
        redirectAttributes.addFlashAttribute("message", "Please select a file to upload");
        return "redirect:/file/status";
    }

    try {
        // Get the file bytes
        byte[] bytes = file.getBytes();
        
        // Extract the file extension safely
        String originalFilename = file.getOriginalFilename();
        String fileExtension = FilenameUtils.getExtension(originalFilename);
        
        // Generate a safe filename with UUID to prevent directory traversal
        String safeFilename = UUID.randomUUID().toString();
        if (fileExtension != null && !fileExtension.isEmpty()) {
            safeFilename += "." + fileExtension;
        }
        
        // Create a safe path within the upload folder
        Path path = Paths.get(UPLOADED_FOLDER).resolve(safeFilename);
        
        // Ensure the path is within the intended directory (additional safety check)
        if (!path.normalize().startsWith(Paths.get(UPLOADED_FOLDER).normalize())) {
            throw new SecurityException("Attempted directory traversal attack");
        }
        
        // Write the file
        Files.write(path, bytes);

        redirectAttributes.addFlashAttribute("message",
                "You successfully uploaded file as '" + safeFilename + "'");

    } catch (IOException e) {
        redirectAttributes.addFlashAttribute("message", "Upload failed");
        logger.error(e.toString());
    } catch (SecurityException e) {
        redirectAttributes.addFlashAttribute("message", "Security violation detected");
        logger.error("Security violation: " + e.toString());
    }

    return "redirect:/file/status";
}


    @GetMapping("/status")
    public String uploadStatus() {
        return "uploadStatus";
    }

    // only upload picture
@PostMapping("/upload/picture")
@ResponseBody
public String uploadPicture(@RequestParam("file") MultipartFile multifile) throws Exception {
    if (multifile.isEmpty()) {
        return "Please select a file to upload";
    }

    String originalFileName = multifile.getOriginalFilename();
    if (originalFileName == null) {
        return "Invalid filename";
    }
    
    // Get file extension safely
    String suffix = FilenameUtils.getExtension(originalFileName);
    if (suffix == null || suffix.isEmpty()) {
        logger.error("[-] No file extension found");
        return "Upload failed. Invalid file format.";
    }
    suffix = "." + suffix.toLowerCase();
    
    String mimeType = multifile.getContentType(); // Get MIME type
    
    // Generate a secure random filename with UUID
    String secureFileName = UUID.randomUUID().toString() + suffix;
    String filePath = UPLOADED_FOLDER + secureFileName;
    File excelFile = convert(multifile);

    // Validate file extension whitelist - check 1
    String[] picSuffixList = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"};
    boolean suffixFlag = false;
    for (String whiteSuffix : picSuffixList) {
        if (suffix.equals(whiteSuffix)) {
            suffixFlag = true;
            break;
        }
    }
    if (!suffixFlag) {
        logger.error("[-] Suffix error: " + suffix);
        deleteFile(filePath);
        return "Upload failed. Illegal picture format.";
    }

    // Validate MIME type against blacklist - check 2
    String[] mimeTypeBlackList = {
            "text/html",
            "text/javascript",
            "application/javascript",
            "application/ecmascript",
            "text/xml",
            "application/xml"
    };
    
    if (mimeType != null) {
        String sanitizedMimeType = SecurityUtil.replaceSpecialStr(mimeType).toLowerCase();
        for (String blackMimeType : mimeTypeBlackList) {
            // Use contains to prevent bypassing with text/html;charset=UTF-8
            if (sanitizedMimeType.contains(blackMimeType)) {
                logger.error("[-] Mime type error: " + mimeType);
                deleteFile(filePath);
                return "Upload failed. Illegal picture format.";
            }
        }
    } else {
        logger.error("[-] Missing mime type");
        deleteFile(filePath);
        return "Upload failed. Unknown file type.";
    }

    // Validate file content is an image - check 3
    boolean isImageFlag = isImage(excelFile);
    deleteFile(randomFilePath); // Note: assuming randomFilePath is defined in the original implementation

    if (!isImageFlag) {
        logger.error("[-] File is not an Image");
        deleteFile(filePath);
        return "Upload failed. File content is not a valid image.";
    }

    try {
        // Create the target directory if it doesn't exist
        File uploadDir = new File(UPLOADED_FOLDER);
        if (!uploadDir.exists()) {
            if (!uploadDir.mkdirs()) {
                logger.error("[-] Failed to create upload directory");
                return "Upload failed. Server error.";
            }
        }
        
        // Create a Path object with normalized path to prevent path traversal
        Path path = Paths.get(UPLOADED_FOLDER).normalize().resolve(secureFileName);
        
        // Validate that the resolved path is within the upload directory
        if (!path.startsWith(Paths.get(UPLOADED_FOLDER).normalize())) {
            logger.error("[-] Path traversal attempt detected");
            return "Upload failed. Security violation.";
        }
        
        // Write the file
        Files.write(path, multifile.getBytes());
    } catch (IOException e) {
        logger.error("[-] File upload error: " + e.toString());
        deleteFile(filePath);
        return "Upload failed: " + e.getMessage();
    }

    logger.info("[+] Safe file. Suffix: null, MIME: null", suffix, mimeType);
    logger.info("[+] Successfully uploaded null", filePath);
    return String.format("File '%s' successfully uploaded as '%s'", originalFileName, secureFileName);
}

        for (String blackMimeType : mimeTypeBlackList) {
            // 用contains是为了防止text/html;charset=UTF-8绕过
            if (SecurityUtil.replaceSpecialStr(mimeType).toLowerCase().contains(blackMimeType)) {
                logger.error("[-] Mime type error: " + mimeType);
                deleteFile(filePath);
                return "Upload failed. Illeagl picture.";
            }
        }

        // 判断文件内容是否是图片 校验3
        boolean isImageFlag = isImage(excelFile);
        deleteFile(randomFilePath);

        if (!isImageFlag) {
            logger.error("[-] File is not Image");
            deleteFile(filePath);
            return "Upload failed. Illeagl picture.";
        }

        try {
            // Generate a secure unique filename instead of using original name
            String secureFileName = UUID.randomUUID().toString() + Suffix;
            
            // Get the file and save it somewhere
            byte[] bytes = multifile.getBytes();
            Path path = Paths.get(UPLOADED_FOLDER).resolve(secureFileName);
            
            // Ensure the resolved path is within the intended directory
            if (!path.normalize().startsWith(Paths.get(UPLOADED_FOLDER).normalize())) {
                return "Security constraint violation";
            }
            
            Files.write(path, bytes);
            filePath = path.toString(); // Update filePath with the actual path used
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: null, MIME: null", Suffix, mimeType);
        logger.info("[+] Successfully uploaded null", filePath);
        return String.format("You successfully uploaded '%s'", filePath);
    }

        }

        // Validate file content is an image (validation 3)
        boolean isImageFlag = isImage(excelFile);
        deleteFile(randomFilePath);

        if (!isImageFlag) {
            logger.error("[-] File is not Image");
            deleteFile(filePath);
            return "Upload failed. Illegal picture.";
        }

        try {
            // Save the file with the sanitized, randomized filename
            byte[] bytes = multifile.getBytes();
            Path path = Paths.get(UPLOADED_FOLDER + safeFilename);
            
            // Normalize and validate the path to ensure it's inside UPLOADED_FOLDER
            Path normalizedPath = path.normalize();
            Path basePath = Paths.get(UPLOADED_FOLDER).normalize();
            
            if (!normalizedPath.startsWith(basePath)) {
                logger.error("[-] Directory traversal attempt detected");
                return "Upload failed due to security violation";
            }
            
            Files.write(path, bytes);
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: null, MIME: null", suffix, mimeType);
        logger.info("[+] Successfully uploaded null", filePath);
        return String.format("You successfully uploaded '%s'", safeFilename);
    }



        try {
            // Get the file and save it somewhere
            byte[] bytes = multifile.getBytes();
            Path path = Paths.get(UPLOADED_FOLDER + multifile.getOriginalFilename());
            Files.write(path, bytes);
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", Suffix, mimeType);
        logger.info("[+] Successfully uploaded {}", filePath);
        return String.format("You successfully uploaded '%s'", filePath);
    }

private void deleteFile(String filePath) {
    if (filePath == null || filePath.isEmpty()) {
        logger.warn("[-] Attempted to delete file with null or empty path");
        return;
    }
    
    try {
        // Normalize and resolve the path to prevent path traversal
        Path path = Paths.get(UPLOADED_FOLDER).normalize().resolve(Paths.get(filePath).getFileName());
        
        // Ensure the file is within the upload directory
        if (!path.startsWith(Paths.get(UPLOADED_FOLDER).normalize())) {
            logger.error("[-] Path traversal attempt detected during file deletion");
            return;
        }
        
        File delFile = path.toFile();
        if (delFile.isFile() && delFile.exists()) {
            if (delFile.delete()) {
                logger.info("[+] null deleted successfully!", path);
                return;
            }
        }
        logger.info("[-] null deletion failed or file does not exist", path);
    } catch (Exception e) {
        logger.error("[-] Error deleting file: null", e.getMessage());
    }
}

        }
        logger.info(filePath + " delete failed!");
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
private File convert(MultipartFile multiFile) throws Exception {
        String originalFileName = multiFile.getOriginalFilename();
        if (originalFileName == null) {
            throw new IllegalArgumentException("Original filename cannot be null");
        }
        
        // Extract just the extension safely
        String extension = FilenameUtils.getExtension(originalFileName);
        if (extension.isEmpty()) {
            extension = "bin"; // Default extension if none is found
        }
        String suffix = "." + extension.toLowerCase();
        
        UUID uuid = Generators.timeBasedGenerator().generate();
        randomFilePath = UPLOADED_FOLDER + uuid.toString() + suffix;
        
        // Create file path securely
        Path resolvedPath = Paths.get(UPLOADED_FOLDER).normalize().resolve(uuid.toString() + suffix).normalize();
        
        // Verify the resolved path is still within the upload directory
        if (!resolvedPath.startsWith(Paths.get(UPLOADED_FOLDER).normalize())) {
            throw new SecurityException("Path traversal attempt detected");
        }
        
        // Create the file using the secure path
        File convFile = resolvedPath.toFile();
        boolean ret = convFile.createNewFile();
        if (!ret) {
            return null;
        }
        
        FileOutputStream fos = new FileOutputStream(convFile);
        fos.write(multiFile.getBytes());
        fos.close();
        return convFile;
    }

        FileOutputStream fos = new FileOutputStream(convFile);
        fos.write(multiFile.getBytes());
        fos.close();
        return convFile;
    }

    /**
     * Check if the file is a picture.
     */
    private static boolean isImage(File file) throws IOException {
        BufferedImage bi = ImageIO.read(file);
        return bi != null;
    }
}
