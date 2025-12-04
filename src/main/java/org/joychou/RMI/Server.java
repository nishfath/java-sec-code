package org.joychou.RMI;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

public static void main(String args[]) {
    try {
        // Set up security properties for SSL/TLS
        System.setProperty("java.security.policy", "server.policy");
        System.setProperty("javax.net.ssl.keyStore", "server_keystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStore", "server_truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        
        // Enable SSL for RMI
        Properties props = System.getProperties();
        props.put("java.rmi.server.useCodebaseOnly", "true");  // Prevent codebase URLs
        props.put("java.rmi.server.hostname", "localhost");    // Specify the hostname
        props.put("java.rmi.server.sslEnabled", "true");       // Enable SSL for RMI
        
        // Initialize Security Manager with custom policy
        if (System.getSecurityManager() == null) {
            System.setSecurityManager(new SecurityManager());
        }
        
        // Create and export the server with specific port and SSL socket factory
        Server obj = new Server();
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, ssf);
        
        // Create a secure registry on port 1099
        Registry registry = LocateRegistry.createRegistry(1099, 
            null, // Default client socket factory
            ssf); // Server socket factory using SSL
        
        // Bind the exported server object to the registry
        registry.bind("Hello", stub);
        
        System.out.println("RMI Server started with security on port 1099");
    } catch (Exception e) {
        System.err.println("Server exception: " + e.toString());
        e.printStackTrace();
    }
}

    }
}

