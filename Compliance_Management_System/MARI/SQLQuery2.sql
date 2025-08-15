USE audit_app;
GO

-- 1. roles (optional reference)
CREATE TABLE dbo.roles (
    role_name VARCHAR(20) PRIMARY KEY  -- 'admin','auditor','user'
);
GO

-- seed roles
INSERT INTO dbo.roles (role_name)
VALUES ('admin'), ('auditor'), ('user');
GO

-- 2. users (if you already created it this is safe; we ensure columns & constraints)
IF OBJECT_ID('dbo.users', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.users (
        id INT IDENTITY PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL REFERENCES dbo.roles(role_name),
        full_name VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        created_at DATETIME2 DEFAULT SYSUTCDATETIME()
    );
END
GO

-- 3. audits (a top-level audit record)
IF OBJECT_ID('dbo.audits', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.audits (
        id INT IDENTITY PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        description VARCHAR(2000) NULL,
        status VARCHAR(50) NOT NULL,       -- 'pending','in_progress','completed','cancelled'
        created_by INT NULL REFERENCES dbo.users(id),
        scheduled_for DATETIME2 NULL,
        compliant BIT NULL,                 -- overall audit compliant flag (nullable until computed)
        created_at DATETIME2 DEFAULT SYSUTCDATETIME()
    );
END
GO

-- 4. audit_items (individual checklist items within an audit)
IF OBJECT_ID('dbo.audit_items', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.audit_items (
        id INT IDENTITY PRIMARY KEY,
        audit_id INT NOT NULL REFERENCES dbo.audits(id) ON DELETE CASCADE,
        item_text VARCHAR(1000) NOT NULL,
        compliant BIT NULL,
        notes VARCHAR(2000) NULL,
        inspected_by INT NULL REFERENCES dbo.users(id),
        inspected_at DATETIME2 NULL,
        created_at DATETIME2 DEFAULT SYSUTCDATETIME()
    );
END
GO

-- 5. audit_status_history (keeps audit status history)
IF OBJECT_ID('dbo.audit_status_history', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.audit_status_history (
        id INT IDENTITY PRIMARY KEY,
        audit_id INT NOT NULL REFERENCES dbo.audits(id) ON DELETE CASCADE,
        old_status VARCHAR(50) NULL,
        new_status VARCHAR(50) NOT NULL,
        changed_by INT NULL REFERENCES dbo.users(id),
        changed_at DATETIME2 DEFAULT SYSUTCDATETIME()
    );
END
GO

-- 6. reports (link to audits)
IF OBJECT_ID('dbo.reports', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.reports (
        id INT IDENTITY PRIMARY KEY,
        audit_id INT NOT NULL REFERENCES dbo.audits(id) ON DELETE CASCADE,
        generated_by INT NULL REFERENCES dbo.users(id),
        generated_at DATETIME2 DEFAULT SYSUTCDATETIME(),
        report_path VARCHAR(500) NULL  -- file path / url if you save reports
    );
END
GO
-- index on audits status (common for pending counts)
CREATE INDEX IX_audits_status ON dbo.audits(status);

-- index on audit_items.audit_id and compliant for compliance aggregations
CREATE INDEX IX_audit_items_audit_compliant ON dbo.audit_items(audit_id, compliant);

-- index on reports.audit_id
CREATE INDEX IX_reports_audit ON dbo.reports(audit_id);

-- index on users.email (unique already exists), add username index if you query by it
CREATE INDEX IX_users_username ON dbo.users(username);
GO
IF OBJECT_ID('dbo.sp_get_metrics', 'P') IS NOT NULL
    DROP PROCEDURE dbo.sp_get_metrics;
GO

CREATE PROCEDURE dbo.sp_get_metrics
AS
BEGIN
    SET NOCOUNT ON;

    -- total audits
    DECLARE @total_audits INT = (SELECT COUNT(1) FROM dbo.audits);

    -- pending (status = 'pending' or 'in_progress' per your business logic)
    DECLARE @pending_audits INT = (
        SELECT COUNT(1)
        FROM dbo.audits
        WHERE status IN ('pending', 'in_progress')
    );

    -- reports generated
    DECLARE @reports_generated INT = (SELECT COUNT(1) FROM dbo.reports);

    -- compliance rate:
    -- compute percent of audit_items that are compliant (only consider items with non-null compliant)
    DECLARE @total_items INT = (
        SELECT COUNT(1) FROM dbo.audit_items WHERE compliant IS NOT NULL
    );
    DECLARE @compliant_items INT = (
        SELECT SUM(CASE WHEN compliant = 1 THEN 1 ELSE 0 END) FROM dbo.audit_items WHERE compliant IS NOT NULL
    );

    DECLARE @compliance_rate DECIMAL(5,2);
    IF @total_items = 0
        SET @compliance_rate = NULL;
    ELSE
        SET @compliance_rate = CASE WHEN @total_items = 0 THEN 0 ELSE (CAST(@compliant_items AS DECIMAL(10,2)) / @total_items) * 100 END;

    SELECT
        @total_audits AS total_audits,
        @pending_audits AS pending_audits,
        CASE WHEN @compliance_rate IS NULL THEN 'N/A' ELSE CONCAT(CONVERT(VARCHAR(10), @compliance_rate), '%') END AS compliance_rate,
        @reports_generated AS reports_generated;
END
GO
-- Example admin insert (placeholder hash - replace with real hash from Flask)
INSERT INTO dbo.users (username, password_hash, role, full_name, email)
VALUES ('admin', '<PLACEHOLDER_HASH>', 'admin', 'System Admin', 'admin@example.com');


