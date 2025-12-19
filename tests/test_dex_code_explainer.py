"""
Tests for DEX Code Explainer

Tests the functionality of the DEX code explanation utility.
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import directly to avoid heavy dependencies
import importlib.util
spec = importlib.util.spec_from_file_location("dex_code_explainer", 
    str(Path(__file__).parent.parent / "utils" / "dex_code_explainer.py"))
dex_explainer_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dex_explainer_module)

DexCodeExplainer = dex_explainer_module.DexCodeExplainer
CodeObfuscationType = dex_explainer_module.CodeObfuscationType


class TestDexCodeExplainer(unittest.TestCase):
    """Test cases for the DexCodeExplainer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.explainer = DexCodeExplainer()
    
    def test_simple_class_explanation(self):
        """Test explanation of a simple class."""
        code = """
        public class SimpleClass {
            private String name;
            
            public String getName() {
                return name;
            }
        }
        """
        
        explanation = self.explainer.explain_code(code)
        
        self.assertIn('summary', explanation)
        self.assertIn('purpose', explanation)
        self.assertIn('obfuscation_techniques', explanation)
        self.assertEqual(len(explanation['key_components']['classes']), 1)
        self.assertIn('SimpleClass', explanation['key_components']['classes'])
    
    def test_drm_code_detection(self):
        """Test detection of DRM-related code."""
        code = """
        package com.example.drm;
        
        import java.util.UUID;
        
        public class DrmHandler {
            private UUID schemeId;
            private byte[] licenseData;
        }
        """
        
        explanation = self.explainer.explain_code(code, package_name="com.example.drm")
        
        self.assertIn('DRM', explanation['purpose'])
        self.assertTrue(any('UUID' in str(c) for c in explanation['security_concerns']))
    
    def test_string_obfuscation_detection(self):
        """Test detection of string array obfuscation."""
        code = """
        public class ObfuscatedStrings {
            private static String[] A04 = {
                "8bdUvaky5WHdDfVtqwXLakhjtGg6hs0c", 
                "CSUdOCO5ftZIoIqJhT3Nbwo3RnwWTbkq"
            };
        }
        """
        
        explanation = self.explainer.explain_code(code)
        
        obfuscation_types = [o['type'] for o in explanation['obfuscation_techniques']]
        self.assertIn(CodeObfuscationType.STRING_ARRAY_OBFUSCATION.value, obfuscation_types)
    
    def test_control_flow_obfuscation_detection(self):
        """Test detection of control flow obfuscation."""
        code = """
        public class ControlFlowObfuscated {
            private static String[] arr = {"test", "data"};
            
            public void check() {
                if (arr[0].charAt(5) != arr[1].charAt(3)) {
                    throw new RuntimeException();
                }
            }
        }
        """
        
        explanation = self.explainer.explain_code(code)
        
        obfuscation_types = [o['type'] for o in explanation['obfuscation_techniques']]
        self.assertIn(CodeObfuscationType.CONTROL_FLOW_OBFUSCATION.value, obfuscation_types)
    
    def test_parcelable_detection(self):
        """Test detection of Android Parcelable implementation."""
        code = """
        import android.os.Parcelable;
        import android.os.Parcel;
        
        public class MyData implements Parcelable {
            @Override
            public int describeContents() {
                return 0;
            }
            
            @Override
            public void writeToParcel(Parcel dest, int flags) {
                dest.writeString(data);
            }
        }
        """
        
        explanation = self.explainer.explain_code(code)
        
        structure_types = [s['type'] for s in explanation['data_structures']]
        self.assertIn('Parcelable', structure_types)
        self.assertIn('Parcelable', explanation['purpose'])
    
    def test_reflection_detection(self):
        """Test detection of Java reflection usage."""
        code = """
        public class ReflectionUser {
            public void loadClass() {
                Class<?> clazz = Class.forName("com.example.HiddenClass");
                Method method = clazz.getDeclaredMethod("hiddenMethod");
            }
        }
        """
        
        explanation = self.explainer.explain_code(code)
        
        obfuscation_types = [o['type'] for o in explanation['obfuscation_techniques']]
        self.assertIn(CodeObfuscationType.REFLECTION.value, obfuscation_types)
    
    def test_native_method_detection(self):
        """Test detection of native methods."""
        code = """
        public class NativeCode {
            public native String nativeMethod();
            
            static {
                System.loadLibrary("native-lib");
            }
        }
        """
        
        explanation = self.explainer.explain_code(code)
        
        obfuscation_types = [o['type'] for o in explanation['obfuscation_techniques']]
        self.assertIn(CodeObfuscationType.NATIVE_METHODS.value, obfuscation_types)
    
    def test_encryption_detection(self):
        """Test detection of encryption usage."""
        code = """
        import javax.crypto.Cipher;
        import javax.crypto.SecretKey;
        
        public class EncryptionHandler {
            public byte[] encrypt(byte[] data, SecretKey key) {
                Cipher cipher = Cipher.getInstance("AES");
                return cipher.doFinal(data);
            }
        }
        """
        
        explanation = self.explainer.explain_code(code)
        
        obfuscation_types = [o['type'] for o in explanation['obfuscation_techniques']]
        self.assertIn(CodeObfuscationType.ENCRYPTION.value, obfuscation_types)
    
    def test_facebook_ads_drm_code(self):
        """Test explanation of the Facebook Ads DRM code example."""
        example_file = Path(__file__).parent.parent / "examples" / "facebook_ads_drm_code.java"
        
        if example_file.exists():
            with open(example_file, 'r') as f:
                code = f.read()
            
            explanation = self.explainer.explain_code(
                code, 
                package_name="com.facebook.ads.internal.exoplayer2.drm"
            )
            
            # Check that it detected key aspects
            self.assertIn('DrmInitData', explanation['key_components']['classes'])
            self.assertIn('SchemeData', explanation['key_components']['classes'])
            
            # Check obfuscation detection
            obf_types = [o['type'] for o in explanation['obfuscation_techniques']]
            self.assertIn(CodeObfuscationType.STRING_ARRAY_OBFUSCATION.value, obf_types)
            self.assertIn(CodeObfuscationType.CONTROL_FLOW_OBFUSCATION.value, obf_types)
            
            # Check purpose inference
            self.assertIn('DRM', explanation['purpose'])
            
            # Check data structures
            structure_types = [s['type'] for s in explanation['data_structures']]
            self.assertIn('Parcelable', structure_types)
    
    def test_format_explanation(self):
        """Test formatting of explanation output."""
        code = """
        public class TestClass {
            private String data;
        }
        """
        
        explanation = self.explainer.explain_code(code)
        formatted = self.explainer.format_explanation(explanation)
        
        self.assertIsInstance(formatted, str)
        self.assertIn('DEX CODE EXPLANATION', formatted)
        self.assertIn('SUMMARY', formatted)
        self.assertIn('PURPOSE', formatted)
        self.assertIn('RECOMMENDATIONS', formatted)
    
    def test_format_explanation_no_technical_details(self):
        """Test formatting without technical details."""
        code = """
        public class TestClass {
            private String data;
        }
        """
        
        explanation = self.explainer.explain_code(code)
        formatted = self.explainer.format_explanation(explanation, include_technical_details=False)
        
        self.assertIsInstance(formatted, str)
        self.assertIn('SUMMARY', formatted)
        # Should not include technical sections
        self.assertNotIn('KEY COMPONENTS', formatted)
    
    def test_security_concerns_byte_arrays(self):
        """Test detection of byte array security concerns."""
        code = """
        import android.os.Parcel;
        
        public class DataHandler {
            private byte[] secretData;
            
            public void writeToParcel(Parcel parcel) {
                parcel.writeByteArray(secretData);
            }
        }
        """
        
        explanation = self.explainer.explain_code(code)
        
        concerns = explanation['security_concerns']
        self.assertTrue(any('Data Handling' in c['category'] for c in concerns))
    
    def test_comparator_detection(self):
        """Test detection of Comparator implementation."""
        code = """
        import java.util.Comparator;
        
        public class MyComparator implements Comparator<String> {
            @Override
            public int compare(String a, String b) {
                return a.compareTo(b);
            }
        }
        """
        
        explanation = self.explainer.explain_code(code)
        
        structure_types = [s['type'] for s in explanation['data_structures']]
        self.assertIn('Comparator', structure_types)
    
    def test_recommendations_generation(self):
        """Test that recommendations are generated."""
        code = """
        public class ObfuscatedClass {
            private static String[] obfStrings = {"longRandomString123456789"};
            public native void nativeCall();
        }
        """
        
        explanation = self.explainer.explain_code(code)
        
        recommendations = explanation['recommendations']
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)
        # Should have recommendations for string deobfuscation and native analysis
        self.assertTrue(any('string' in r.lower() for r in recommendations))
    
    def test_package_name_inference(self):
        """Test that package name helps with purpose inference."""
        code = """
        public class Handler {
            private String data;
        }
        """
        
        # Without package name
        explanation1 = self.explainer.explain_code(code)
        
        # With DRM-related package name
        explanation2 = self.explainer.explain_code(code, package_name="com.example.drm")
        
        # With Ads-related package name
        explanation3 = self.explainer.explain_code(code, package_name="com.facebook.ads")
        
        self.assertIn('DRM', explanation2['purpose'])
        self.assertIn('Advertisement', explanation3['purpose'])


class TestDexCodeExplainerConvenience(unittest.TestCase):
    """Test convenience functions."""
    
    def test_explain_dex_code_snippet(self):
        """Test the convenience function."""
        # Use the already loaded module
        explain_dex_code_snippet = dex_explainer_module.explain_dex_code_snippet
        
        code = """
        public class SimpleClass {
            private String data;
        }
        """
        
        result = explain_dex_code_snippet(code)
        
        self.assertIsInstance(result, str)
        self.assertIn('DEX CODE EXPLANATION', result)


if __name__ == '__main__':
    unittest.main()
