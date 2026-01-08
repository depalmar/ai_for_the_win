-- AI Security Labs Database Schema
-- Initialize tables for security analysis labs

-- Security Events Table
CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    event_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    source_ip INET,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(10),
    payload TEXT,
    raw_log TEXT,
    parsed_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index for common queries
CREATE INDEX idx_events_time ON security_events(event_time);
CREATE INDEX idx_events_type ON security_events(event_type);
CREATE INDEX idx_events_severity ON security_events(severity);
CREATE INDEX idx_events_source_ip ON security_events(source_ip);

-- User Activity Table
CREATE TABLE IF NOT EXISTS user_activity (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL,
    activity_type VARCHAR(50) NOT NULL,
    activity_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resource_accessed VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    metadata JSONB
);

CREATE INDEX idx_activity_user ON user_activity(user_id);
CREATE INDEX idx_activity_time ON user_activity(activity_time);

-- IOC (Indicators of Compromise) Table
CREATE TABLE IF NOT EXISTS iocs (
    id SERIAL PRIMARY KEY,
    ioc_type VARCHAR(50) NOT NULL,
    ioc_value VARCHAR(500) NOT NULL,
    confidence_score DECIMAL(3,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    source VARCHAR(100),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    tags TEXT[],
    metadata JSONB,
    UNIQUE(ioc_type, ioc_value)
);

CREATE INDEX idx_iocs_type ON iocs(ioc_type);
CREATE INDEX idx_iocs_value ON iocs(ioc_value);

-- ML Model Predictions Table
CREATE TABLE IF NOT EXISTS ml_predictions (
    id SERIAL PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(50),
    input_hash VARCHAR(64),
    prediction VARCHAR(100),
    confidence DECIMAL(5,4),
    prediction_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    latency_ms INTEGER,
    input_features JSONB,
    metadata JSONB
);

CREATE INDEX idx_predictions_model ON ml_predictions(model_name);
CREATE INDEX idx_predictions_time ON ml_predictions(prediction_time);

-- Alert Table
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    alert_id UUID DEFAULT gen_random_uuid(),
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    assigned_to VARCHAR(100),
    status VARCHAR(20) DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE')),
    related_events INTEGER[],
    metadata JSONB
);

CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_created ON alerts(created_at);

-- Investigation Cases Table
CREATE TABLE IF NOT EXISTS investigation_cases (
    id SERIAL PRIMARY KEY,
    case_id UUID DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(20) DEFAULT 'OPEN',
    priority VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    closed_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(100),
    assigned_to VARCHAR(100),
    related_alerts INTEGER[],
    findings TEXT,
    timeline JSONB,
    metadata JSONB
);

CREATE INDEX idx_cases_status ON investigation_cases(status);

-- Insert sample data for labs
INSERT INTO iocs (ioc_type, ioc_value, confidence_score, source, tags) VALUES
    ('ip', '192.168.1.100', 0.85, 'threat_intel_feed', ARRAY['suspicious', 'scanning']),
    ('domain', 'malware-c2.evil.com', 0.95, 'malware_analysis', ARRAY['c2', 'malware']),
    ('hash_sha256', 'a1b2c3d4e5f6...', 0.90, 'sandbox_analysis', ARRAY['malware', 'trojan']),
    ('email', 'phisher@evil.com', 0.75, 'phishing_report', ARRAY['phishing']);

-- Create view for security dashboard
CREATE VIEW security_dashboard AS
SELECT
    date_trunc('hour', event_time) as time_bucket,
    event_type,
    severity,
    COUNT(*) as event_count
FROM security_events
WHERE event_time > NOW() - INTERVAL '24 hours'
GROUP BY time_bucket, event_type, severity
ORDER BY time_bucket DESC;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO labuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO labuser;
