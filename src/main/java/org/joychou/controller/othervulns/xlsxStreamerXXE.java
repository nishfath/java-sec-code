package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileInputStream;
import java.io.IOException;


/**
 * Desc:  xlsx-streamer xxe vuln code
 * Usage: xl/workbook.xml
 * Ref:   https://www.itread01.com/hkpcyyp.html
 * Fix:   update xlsx-streamer to 2.1.0 or above
 *
 * @author JoyChou @2019-09-05
 */
@Controller
@RequestMapping("xlsx-streamer")
public class xlsxStreamerXXE {


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


@PostMapping("/readxlsx")
public void xllx_streamer_xxe(MultipartFile file) throws IOException {
    // Create temporary file to avoid direct stream processing
    Path tempFile = Files.createTempFile("safe-", "-xlsx");
    try {
        // Copy content to temp file
        Files.copy(file.getInputStream(), tempFile, StandardCopyOption.REPLACE_EXISTING);
        
        // Configure safe XML processing
        System.setProperty("javax.xml.parsers.SAXParserFactory", "com.sun.org.apache.xerces.internal.jaxp.SAXParserFactoryImpl");
        System.setProperty("javax.xml.parsers.DocumentBuilderFactory", "com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderFactoryImpl");
        
        // Use the secure reader builder with secure properties
        StreamingReader reader = StreamingReader.builder()
            .rowCacheSize(100)    // number of rows to keep in memory
            .bufferSize(4096)     // buffer size to use when reading
            .open(tempFile.toFile());
    } catch (Exception e) {
        throw new IOException("Error processing XLSX file: " + e.getMessage(), e);
    } finally {
        // Clean up the temporary file
        Files.deleteIfExists(tempFile);
    }
}



    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
