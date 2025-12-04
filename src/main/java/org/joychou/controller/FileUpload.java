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

        // Extract filename safely
        String originalFilename = multifile.getOriginalFilename();
        if (originalFilename == null) {
            return "Invalid filename";
        }
        
        // Extract file extension using a safe method
        String extension = FilenameUtils.getExtension(originalFilename);
        if (extension == null || extension.isEmpty()) {
            return "File must have an extension";
        }
        
        // Generate a secure random filename with the original extension
        String secureFilename = UUID.randomUUID().toString() + "." + extension;
        String Suffix = "." + extension.toLowerCase();
        String mimeType = multifile.getContentType(); // Get MIME type
        
        // Create safe file path with the secure filename
        String filePath = UPLOADED_FOLDER + secureFilename;
        File excelFile = convert(multifile);

        // Validate file extension against whitelist (check 1)
        String[] picSuffixList = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"};
        boolean suffixFlag = false;
        for (String white_suffix : picSuffixList) {
            if (Suffix.toLowerCase().equals(white_suffix)) {
                suffixFlag = true;
                break;
            }
        }
        if (!suffixFlag) {
            logger.error("[-] Suffix error: " + Suffix);
            deleteFile(filePath);
            return "Upload failed. Illegal picture format.";
        }

        // Check MIME type against blacklist (check 2)
        String[] mimeTypeBlackList = {
                "text/html",
                "text/javascript",
                "application/javascript",
                "application/ecmascript",
                "text/xml",
                "application/xml"
        };
        for (String blackMimeType : mimeTypeBlackList) {
            // Use contains to prevent bypasses like text/html;charset=UTF-8
            if (SecurityUtil.replaceSpecialStr(mimeType).toLowerCase().contains(blackMimeType)) {
                logger.error("[-] Mime type error: " + mimeType);
                deleteFile(filePath);
                return "Upload failed. Illegal picture format.";
            }
        }

        // Verify file is actually an image (check 3)
        boolean isImageFlag = isImage(excelFile);
        deleteFile(randomFilePath); // Note: There appears to be an undefined variable "randomFilePath" in the original code

        if (!isImageFlag) {
            logger.error("[-] File is not an Image");
            deleteFile(filePath);
            return "Upload failed. Illegal picture format.";
        }

        try {
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
        String fileName = multiFile.getOriginalFilename();
        String suffix = fileName.substring(fileName.lastIndexOf("."));
        UUID uuid = Generators.timeBasedGenerator().generate();
        randomFilePath = UPLOADED_FOLDER + uuid + suffix;
        // 随机生成一个同后缀名的文件
        File convFile = new File(randomFilePath);
        boolean ret = convFile.createNewFile();
        if (!ret) {
            return null;
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
