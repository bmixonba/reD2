#!/usr/bin/env python3
"""
Example usage demonstration for the APK LLM Annotation Pipeline.

This script demonstrates how to use the pipeline with different configurations
and shows example outputs.
"""

import os
import sys
import json
import tempfile
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from scripts.apk_llm_annotation_pipeline import (
    JavaCodeAnnotator, 
    SOCodeAnnotator, 
    PromptGenerator,
    APKLLMAnnotationPipeline
)


def create_sample_java_files():
    """Create sample Java files for testing."""
    samples = {
        'CryptoUtils.java': '''
package com.example.security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoUtils {
    private static final String ALGORITHM = "AES";
    
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(256, new SecureRandom());
        return keyGen.generateKey();
    }
    
    public static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }
}
''',
        
        'NetworkManager.java': '''
package com.example.network;

import java.net.HttpURLConnection;
import java.net.URL;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

public class NetworkManager {
    private static final String USER_AGENT = "MyApp/1.0";
    
    public String sendGetRequest(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        connection.setRequestMethod("GET");
        connection.setRequestProperty("User-Agent", USER_AGENT);
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        
        return response.toString();
    }
    
    public String sendPostRequest(String urlString, String data) throws Exception {
        URL url = new URL(urlString);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setDoOutput(true);
        
        try (OutputStream os = connection.getOutputStream()) {
            os.write(data.getBytes());
        }
        
        return readResponse(connection);
    }
    
    private String readResponse(HttpURLConnection connection) throws Exception {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        
        return response.toString();
    }
}
''',

        'AuthenticationActivity.java': '''
package com.example.auth;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.util.Base64;
import java.security.KeyStore;
import javax.crypto.Cipher;

public class AuthenticationActivity {
    private static final String PREFS_NAME = "auth_prefs";
    private static final String KEY_TOKEN = "auth_token";
    private static final String KEYSTORE_ALIAS = "user_auth_key";
    
    private Context context;
    private BiometricManager biometricManager;
    
    public AuthenticationActivity(Context context) {
        this.context = context;
        this.biometricManager = BiometricManager.from(context);
    }
    
    public boolean authenticateUser(String username, String password) {
        // Validate credentials against stored hash
        String storedHash = getStoredPasswordHash(username);
        String inputHash = hashPassword(password);
        
        if (storedHash != null && storedHash.equals(inputHash)) {
            generateAuthToken(username);
            return true;
        }
        return false;
    }
    
    public void enableBiometricAuth() {
        if (biometricManager.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS) {
            // Setup biometric authentication
            setupBiometricPrompt();
        }
    }
    
    private String hashPassword(String password) {
        // Simple example - real implementation should use proper hashing
        return Base64.encodeToString(password.getBytes(), Base64.DEFAULT);
    }
    
    private String getStoredPasswordHash(String username) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        return prefs.getString(username + "_hash", null);
    }
    
    private void generateAuthToken(String username) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            
            // Generate and store authentication token
            String token = "auth_" + System.currentTimeMillis() + "_" + username;
            storeAuthToken(token);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void storeAuthToken(String token) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit().putString(KEY_TOKEN, token).apply();
    }
    
    private void setupBiometricPrompt() {
        // Biometric setup implementation
    }
}
'''
    }
    
    return samples


def demonstrate_java_annotation():
    """Demonstrate Java code annotation capabilities."""
    print("="*60)
    print("JAVA CODE ANNOTATION DEMONSTRATION")
    print("="*60)
    
    annotator = JavaCodeAnnotator()
    samples = create_sample_java_files()
    
    for filename, code in samples.items():
        print(f"\nAnalyzing: {filename}")
        print("-" * 40)
        
        annotation = annotator.annotate_java_file(filename, code)
        
        print(f"Detected labels: {', '.join(annotation.labels)}")
        print(f"Confidence: {annotation.confidence:.2f}")
        print(f"Methods detected: {annotation.analysis_data.get('method_count', 0)}")
        print(f"Classes detected: {annotation.analysis_data.get('class_count', 0)}")
        print(f"Imports detected: {annotation.analysis_data.get('import_count', 0)}")
        
        if annotation.analysis_data.get('detected_patterns'):
            print("Pattern matches:")
            for category, matches in annotation.analysis_data['detected_patterns'].items():
                print(f"  {category}: {matches[:3]}")  # Show first 3 matches


def demonstrate_prompt_generation():
    """Demonstrate prompt/completion pair generation."""
    print("\n" + "="*60)
    print("PROMPT/COMPLETION GENERATION DEMONSTRATION")
    print("="*60)
    
    annotator = JavaCodeAnnotator()
    prompt_gen = PromptGenerator()
    
    # Use the crypto utility sample
    samples = create_sample_java_files()
    crypto_code = samples['CryptoUtils.java']
    
    annotation = annotator.annotate_java_file('CryptoUtils.java', crypto_code)
    pairs = prompt_gen.generate_prompt_completion_pairs(annotation, max_pairs_per_file=3)
    
    print(f"\nGenerated {len(pairs)} prompt/completion pairs from CryptoUtils.java")
    
    for i, pair in enumerate(pairs, 1):
        print(f"\n--- Pair {i} ({pair.metadata['template_name']}) ---")
        print("PROMPT:")
        print(pair.prompt[:300] + "..." if len(pair.prompt) > 300 else pair.prompt)
        print("\nCOMPLETION:")
        print(pair.completion[:300] + "..." if len(pair.completion) > 300 else pair.completion)
        print(f"\nMetadata: Labels={pair.metadata['labels']}, Confidence={pair.metadata['confidence']:.2f}")


def demonstrate_output_format():
    """Demonstrate JSONL output format."""
    print("\n" + "="*60)
    print("OUTPUT FORMAT DEMONSTRATION")
    print("="*60)
    
    annotator = JavaCodeAnnotator()
    prompt_gen = PromptGenerator()
    
    # Generate sample training data
    samples = create_sample_java_files()
    all_pairs = []
    
    for filename, code in samples.items():
        annotation = annotator.annotate_java_file(filename, code)
        pairs = prompt_gen.generate_prompt_completion_pairs(annotation, max_pairs_per_file=2)
        all_pairs.extend(pairs)
    
    # Save to temporary file to demonstrate format
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        for pair in all_pairs:
            json.dump({
                'prompt': pair.prompt,
                'completion': pair.completion,
                'metadata': pair.metadata
            }, f, ensure_ascii=False)
            f.write('\n')
        
        temp_path = f.name
    
    print(f"Generated {len(all_pairs)} training pairs")
    print(f"Sample JSONL output saved to: {temp_path}")
    
    # Show first few lines
    print("\nSample JSONL content:")
    with open(temp_path, 'r') as f:
        for i, line in enumerate(f):
            if i >= 2:  # Show only first 2 lines
                break
            data = json.loads(line)
            print(f"Line {i+1}:")
            print(f"  Prompt: {data['prompt'][:100]}...")
            print(f"  Completion: {data['completion'][:100]}...")
            print(f"  Labels: {data['metadata']['labels']}")
            print()
    
    # Clean up
    os.unlink(temp_path)


def demonstrate_so_annotation():
    """Demonstrate SO file annotation (mock example since we don't have real SO files)."""
    print("\n" + "="*60)
    print("SO FILE ANNOTATION DEMONSTRATION")
    print("="*60)
    
    annotator = SOCodeAnnotator()
    
    print("SO Annotator initialized")
    print(f"PyGhidra available: {annotator.ghidra_available}")
    print(f"Status: {annotator.ghidra_status}")
    
    # Show available annotation patterns
    print("\nAvailable SO annotation categories:")
    for category in annotator.annotation_patterns.keys():
        readable_name = category.replace('_', ' ').title()
        print(f"  - {readable_name}")
    
    print("\nNote: SO file analysis requires actual binary files.")
    print("The pipeline will automatically extract and analyze .so files from APKs.")


def demonstrate_pipeline_configuration():
    """Demonstrate pipeline configuration options."""
    print("\n" + "="*60)
    print("PIPELINE CONFIGURATION DEMONSTRATION")
    print("="*60)
    
    # Initialize pipeline with custom settings
    pipeline = APKLLMAnnotationPipeline(
        output_format='jsonl',
        verbose=True
    )
    
    # Show configuration options
    print(f"Default max Java files per APK: {pipeline.max_java_files}")
    print(f"Default max SO files per APK: {pipeline.max_so_files}")
    print(f"Default max pairs per file: {pipeline.max_pairs_per_file}")
    print(f"Output format: {pipeline.output_format}")
    
    # Show customization
    pipeline.max_java_files = 100
    pipeline.max_so_files = 20
    pipeline.max_pairs_per_file = 5
    
    print(f"\nAfter customization:")
    print(f"Max Java files per APK: {pipeline.max_java_files}")
    print(f"Max SO files per APK: {pipeline.max_so_files}")
    print(f"Max pairs per file: {pipeline.max_pairs_per_file}")


def main():
    """Run all demonstrations."""
    print("APK LLM ANNOTATION PIPELINE - EXAMPLE USAGE")
    print("This demonstration shows the capabilities of the annotation pipeline.")
    print("Note: Full APK processing requires actual APK files.")
    
    try:
        demonstrate_java_annotation()
        demonstrate_prompt_generation()
        demonstrate_output_format()
        demonstrate_so_annotation()
        demonstrate_pipeline_configuration()
        
        print("\n" + "="*60)
        print("EXAMPLE USAGE COMMANDS")
        print("="*60)
        print("# Process single APK:")
        print("python scripts/apk_llm_annotation_pipeline.py --input-apk app.apk --output training.jsonl")
        print()
        print("# Process directory with report:")
        print("python scripts/apk_llm_annotation_pipeline.py --input-dir apks/ --output-dir corpus/ --report")
        print()
        print("# Custom configuration:")
        print("python scripts/apk_llm_annotation_pipeline.py \\")
        print("  --input-apk app.apk \\")
        print("  --output training.jsonl \\")
        print("  --max-java-files 100 \\")
        print("  --max-so-files 20 \\")
        print("  --max-pairs-per-file 5 \\")
        print("  --verbose")
        
        print("\n" + "="*60)
        print("DEMONSTRATION COMPLETED SUCCESSFULLY")
        print("="*60)
        
    except Exception as e:
        print(f"\nError during demonstration: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())