import java.sql.*;
import java.io.*;
import java.util.*;
import java.security.*;

public class VulnerableApp {
    // CWE-798: Hardcoded credentials
    private static final String DB_PASSWORD = "secret123";
    private static final String API_KEY = "sk-prod-key-abc12345";
    
    // CWE-89: SQL Injection
    public String getUserData(HttpServletRequest request) throws Exception {
        String username = request.getParameter("username");
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        
        // Direct string concatenation - SQL injection!
        String query = "SELECT * FROM users WHERE name = '" + username + "'";
        ResultSet rs = stmt.executeQuery(query);
        
        // CWE-476: Potential NPE
        String result = rs.getString("data");
        result.length();  // NPE if result is null
        
        return result;
    }
    
    // CWE-78: Command injection
    public void executeCommand(HttpServletRequest request) throws Exception {
        String cmd = request.getHeader("X-Command");
        Runtime.getRuntime().exec(cmd);  // taint: getHeader -> exec
    }
    
    // CWE-327: Weak crypto
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return new String(hash);
    }
    
    // CWE-390: Empty catch / exception swallowing
    public void processData(String data) {
        try {
            riskyOperation(data);
        } catch (Exception e) {
            // empty - swallows all errors silently
        }
    }
    
    // CWE-597: Wrong string comparison
    public boolean checkRole(String role) {
        String userRole = getRole();
        if (userRole == "admin") {  // should use .equals()
            return true;
        }
        return false;
    }
    
    private void riskyOperation(String d) throws Exception {}
    private String getRole() { return "user"; }
}
