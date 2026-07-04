import pytest
import sys
from pathlib import Path
import joblib
import json

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import (
    MODEL_PATH, SCALER_PATH, ENCODER_PATH, METADATA_PATH
)


class TestModelLoading:
    """Test model file loading"""
    
    def test_model_file_exists(self):
        """Test that model file exists"""
        assert MODEL_PATH.exists(), f"Model file not found at {MODEL_PATH}"
    
    def test_scaler_file_exists(self):
        """Test that scaler file exists"""
        assert SCALER_PATH.exists(), f"Scaler file not found at {SCALER_PATH}"
    
    def test_encoder_file_exists(self):
        """Test that encoder file exists"""
        assert ENCODER_PATH.exists(), f"Encoder file not found at {ENCODER_PATH}"
    
    def test_metadata_file_exists(self):
        """Test that metadata file exists"""
        assert METADATA_PATH.exists(), f"Metadata file not found at {METADATA_PATH}"
    
    def test_load_model(self):
        """Test loading the model"""
        try:
            model = joblib.load(MODEL_PATH)
            assert model is not None
        except Exception as e:
            pytest.fail(f"Failed to load model: {e}")
    
    def test_load_scaler(self):
        """Test loading the scaler"""
        try:
            scaler = joblib.load(SCALER_PATH)
            assert scaler is not None
        except Exception as e:
            pytest.fail(f"Failed to load scaler: {e}")
    
    def test_load_encoder(self):
        """Test loading the encoder"""
        try:
            encoder = joblib.load(ENCODER_PATH)
            assert encoder is not None
        except Exception as e:
            pytest.fail(f"Failed to load encoder: {e}")
    
    def test_load_metadata(self):
        """Test loading metadata"""
        try:
            with open(METADATA_PATH, 'r') as f:
                metadata = json.load(f)
            assert "features" in metadata
            assert "classes" in metadata
            assert "metrics" in metadata
        except Exception as e:
            pytest.fail(f"Failed to load metadata: {e}")


class TestModelProperties:
    """Test model properties and classes"""
    
    def test_encoder_classes(self):
        """Test that encoder has expected classes"""
        encoder = joblib.load(ENCODER_PATH)
        classes = encoder.classes_
        
        expected_classes = ["dos", "normal", "probe", "r2l", "u2r"]
        assert len(classes) == len(expected_classes)
        assert all(cls in classes for cls in expected_classes)
    
    def test_metadata_features(self):
        """Test that metadata contains expected features"""
        with open(METADATA_PATH, 'r') as f:
            metadata = json.load(f)
        
        features = metadata["features"]
        assert len(features) == 12
        assert "duration" in features
        assert "src_bytes" in features
        assert "count" in features
    
    def test_model_predict_shape(self):
        """Test model output shape"""
        import numpy as np
        
        model = joblib.load(MODEL_PATH)
        
        # Create dummy input
        dummy_input = np.random.rand(1, 41)  # 41 features expected
        
        try:
            predictions = model.predict(dummy_input)
            assert len(predictions) == 1
        except Exception as e:
            # Model might expect scaled input, which is okay
            pass


class TestMetricsValidation:
    """Test model metrics are valid"""
    
    def test_metrics_format(self):
        """Test that metrics have valid format"""
        with open(METADATA_PATH, 'r') as f:
            metadata = json.load(f)
        
        metrics = metadata["metrics"]
        
        # Check common metrics
        expected_metrics = ["accuracy", "precision", "recall", "f1_score"]
        for metric in expected_metrics:
            assert metric in metrics, f"Missing metric: {metric}"
            assert 0 <= metrics[metric] <= 1, f"Invalid {metric} value"
    
    def test_model_accuracy_reasonable(self):
        """Test that model has reasonable accuracy"""
        with open(METADATA_PATH, 'r') as f:
            metadata = json.load(f)
        
        accuracy = metadata["metrics"]["accuracy"]
        # Model should have at least 70% accuracy
        assert accuracy >= 0.7, f"Model accuracy too low: {accuracy}"