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
            // Get the file and save it somewhere
            byte[] bytes = file.getBytes();
            Path path = Paths.get(UPLOADED_FOLDER + file.getOriginalFilename());
            Files.write(path, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + UPLOADED_FOLDER + file.getOriginalFilename() + "'");

        } catch (IOException e) {
            redirectAttributes.addFlashAttribute("message", "upload failed");
            logger.error(e.toString());
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
    
    // Extract file extension safely
    String suffix = "";
    int lastDotIndex = originalFileName.lastIndexOf(".");
    if (lastDotIndex > 0) {
        suffix = originalFileName.substring(lastDotIndex);
    }
    
    String mimeType = multifile.getContentType(); // Get MIME type
    
    // Generate a secure random filename to prevent directory traversal
    UUID uuid = Generators.timeBasedGenerator().generate();
    String secureFileName = uuid + suffix;
    String filePath = UPLOADED_FOLDER + secureFileName;
    
    // Convert multifile to a temporary file for inspection
    File excelFile = convert(multifile);
    if (excelFile == null) {
        return "File creation failed";
    }

    // Check if file suffix is in whitelist - validation 1
    String[] picSuffixList = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"};
    boolean suffixFlag = false;
    for (String white_suffix : picSuffixList) {
        if (suffix.toLowerCase().equals(white_suffix)) {
            suffixFlag = true;
            break;
        }
    }
    if (!suffixFlag) {
        logger.error("[-] Suffix error: " + suffix);
        deleteFile(filePath);
        return "Upload failed. Illegal picture format.";
    }

    // Check if MIME type is in blacklist - validation 2
    String[] mimeTypeBlackList = {
            "text/html",
            "text/javascript",
            "application/javascript",
            "application/ecmascript",
            "text/xml",
            "application/xml"
    };
    for (String blackMimeType : mimeTypeBlackList) {
        // Contains check to prevent bypass like text/html;charset=UTF-8
        if (SecurityUtil.replaceSpecialStr(mimeType).toLowerCase().contains(blackMimeType)) {
            logger.error("[-] Mime type error: " + mimeType);
            deleteFile(filePath);
            return "Upload failed. Illegal picture format.";
        }
    }

    // Check if file content is actually an image - validation 3
    boolean isImageFlag = isImage(excelFile);
    deleteFile(randomFilePath);

    if (!isImageFlag) {
        logger.error("[-] File is not Image");
        deleteFile(filePath);
        return "Upload failed. Illegal picture format.";
    }

    try {
        // Save file using the secure filename
        byte[] bytes = multifile.getBytes();
        Path path = Paths.get(UPLOADED_FOLDER + secureFileName);
        
        // Validate the path is within the intended directory
        if (!path.normalize().startsWith(Paths.get(UPLOADED_FOLDER).normalize())) {
            logger.error("[-] Path traversal attempt detected");
            return "Upload failed. Invalid path.";
        }
        
        Files.write(path, bytes);
    } catch (IOException | InvalidPathException e) {
        logger.error(e.toString());
        deleteFile(filePath);
        return "Upload failed";
    }

    logger.info("[+] Safe file. Suffix: null, MIME: null", suffix, mimeType);
    logger.info("[+] Successfully uploaded null (original: null)", filePath, originalFileName);
    return String.format("You successfully uploaded '%s'", secureFileName);
}

            // Get the file content and save it to the secure path
            byte[] bytes = multifile.getBytes();
            
            // Create a safe Path object using the secure filename
            Path path = Paths.get(UPLOADED_FOLDER, secureFilename);
            
            // Verify the final path is within the intended directory
            Path normalizedPath = path.normalize();
            Path targetDirPath = Paths.get(UPLOADED_FOLDER).normalize();
            
            if (!normalizedPath.startsWith(targetDirPath)) {
                logger.error("[-] Directory traversal attempt detected");
                return "Upload failed. Security violation.";
            }
            
            Files.write(path, bytes);
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: null, MIME: null", Suffix, mimeType);
        logger.info("[+] Successfully uploaded null", filePath);
        return String.format("You successfully uploaded '%s'", secureFilename);
    }

            // Validate that the resulting path is within the intended directory
            Path normalizedPath = path.normalize();
            if (!normalizedPath.startsWith(Paths.get(UPLOADED_FOLDER).normalize())) {
                logger.error("[-] Directory traversal attempt detected");
                return "Upload failed. Security violation.";
            }
            
            Files.write(path, bytes);
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: null, MIME: null", suffix, mimeType);
        logger.info("[+] Successfully uploaded null", filePath);
        return String.format("You successfully uploaded '%s' as '%s'", originalFileName, secureFileName);
    }


private void deleteFile(String filePath) {
        try {
            // Normalize the path
            Path path = Paths.get(filePath).normalize();
            Path targetDirPath = Paths.get(UPLOADED_FOLDER).normalize();
            
            // Verify the path is within the intended directory
            if (!path.startsWith(targetDirPath)) {
                logger.error("[-] Directory traversal attempt detected during file deletion: " + filePath);
                return;
            }
            
            File delFile = path.toFile();
            if(delFile.isFile() && delFile.exists()) {
                if (delFile.delete()) {
                    logger.info("[+] " + filePath + " deleted successfully!");
                    return;
                }
            }
            logger.info(filePath + " delete failed!");
        } catch (Exception e) {
            logger.error("Error during file deletion: " + e.getMessage());
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
    if (multiFile == null || multiFile.getOriginalFilename() == null) {
        return null;
    }
    
    // Extract file extension safely
    String originalFileName = multiFile.getOriginalFilename();
    String suffix = "";
    int lastDotIndex = originalFileName.lastIndexOf(".");
    if (lastDotIndex > 0) {
        suffix = originalFileName.substring(lastDotIndex);
    }
    
    // Generate a secure random filename with UUID
    UUID uuid = Generators.timeBasedGenerator().generate();
    randomFilePath = UPLOADED_FOLDER + uuid + suffix;
    
    // Create a temporary file for inspection
    File convFile = new File(randomFilePath);
    
    // Validate the path is within the intended directory
    Path path = convFile.toPath().normalize();
    if (!path.startsWith(Paths.get(UPLOADED_FOLDER).normalize())) {
        logger.error("[-] Path traversal attempt detected");
        return null;
    }
    
    boolean ret = convFile.createNewFile();
    if (!ret) {
        return null;
    }
    
    try (FileOutputStream fos = new FileOutputStream(convFile)) {
        fos.write(multiFile.getBytes());
    }
    
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
