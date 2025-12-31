# Testing Conventions

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Skip slow tests
pytest -m "not slow"

# Skip tests requiring API keys
pytest -m "not requires_api"

# Run specific lab tests
pytest tests/test_lab01_phishing_classifier.py -v

# With coverage
pytest tests/ --cov=labs --cov-report=html
```

## Test Markers

Use pytest markers appropriately:

```python
import pytest

@pytest.mark.slow
def test_large_dataset():
    """Test that takes a long time."""
    pass

@pytest.mark.requires_api
def test_virustotal_lookup():
    """Test requiring VirusTotal API key."""
    pass

@pytest.mark.integration
def test_full_pipeline():
    """Integration test with external services."""
    pass
```

## Writing Tests

- Use pytest fixtures for common setup
- Mark slow tests with `@pytest.mark.slow`
- Mark API-dependent tests with `@pytest.mark.requires_api`
- Aim for 80%+ coverage on solution code
- Include edge cases and error paths

## Test Structure

```python
class TestFeatureName:
    """Tests for feature description."""

    @pytest.fixture
    def sample_data(self) -> dict:
        """Fixture providing test data."""
        return {"key": "value"}

    def test_valid_input(self, sample_data: dict) -> None:
        """Test normal operation."""
        result = function_under_test(sample_data)
        assert result is not None

    def test_invalid_input_raises(self) -> None:
        """Test that invalid input raises error."""
        with pytest.raises(ValueError):
            function_under_test(None)
```
