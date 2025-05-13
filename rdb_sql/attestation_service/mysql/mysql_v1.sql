CREATE TABLE IF NOT EXISTS T_DB_VERSION (
    NAME VARCHAR(32) NOT NULL,
    VERSION VARCHAR(32) NOT NULL
);

CREATE TABLE IF NOT EXISTS key_manager_key_version (
    key_version VARCHAR(32) NOT NULL,
    key_type VARCHAR(32) NOT NULL
);


CREATE TABLE IF NOT EXISTS policy_information (
    policy_id           VARCHAR(36)    NOT NULL    COMMENT 'Policy ID (Primary Key)',
    policy_name         VARCHAR(255)   NOT NULL    COMMENT 'Policy Name',
    policy_description  VARCHAR(512)   NULL        COMMENT 'Policy Description',
    policy_content      LONGTEXT       NOT NULL    COMMENT 'Policy Content',
    is_default          BOOLEAN        NOT NULL    COMMENT 'Whether it is the default policy',
    policy_version      INTEGER        NOT NULL    COMMENT 'Policy Version',
    create_time         BIGINT         NOT NULL    COMMENT 'Policy Creation Time',
    update_time         BIGINT         NOT NULL    COMMENT 'Policy Update Time',
    user_id             VARCHAR(36)    NOT NULL    COMMENT 'User ID who created the policy',
    attester_type       JSON           NOT NULL    COMMENT 'List of supported challenge plugin types',
    signature           VARBINARY(512) NULL        COMMENT 'Policy Signature',
    valid_code          INTEGER        NOT NULL    COMMENT 'Verification Status: 0-Normal, 1-Verification Failed',
    key_version         VARCHAR(32)    NULL        COMMENT 'Signature Key Version',
    product_name        VARCHAR(128)   NULL        COMMENT 'Reserved field',
    product_type        VARCHAR(128)   NULL        COMMENT 'Reserved field',
    board_type          VARCHAR(128)   NULL        COMMENT 'Reserved field',
    PRIMARY KEY (policy_id),
    INDEX idx_user_id (user_id)
);

create table IF NOT EXISTS t_cert_info
(
    id          varchar(32) default '' not null comment 'Certificate ID, hash generated from certificate serial number, issuer, and user_id'
    primary key,
    serial_num  varchar(40)            null comment 'Certificate serial number',
    user_id     varchar(64)            null comment 'User ID',
    type        JSON                   null comment 'Certificate type',
    name        varchar(255)           null comment 'Certificate name',
    issuer      varchar(255)           null comment 'Certificate issuer',
    owner       varchar(255)           null comment 'Certificate owner',
    cert_info   blob                   null comment 'Certificate content',
    is_default  tinyint(1)             null comment 'Whether it is the default',
    description varchar(512)           null comment 'Description',
    version     int                    null comment 'Certificate version, similar to v1.0, also used for optimistic locking to ensure multi-threaded updates',
    create_time bigint(1)              null comment 'Certificate creation time',
    update_time bigint(1)              null comment 'Certificate update time',
    signature   varbinary(512)         null comment 'Signature for integrity verification',
    key_version varchar(36)            null comment 'Version of the key used for signing',
    key_id      varchar(128)           null comment 'ID of the key used for signing',
    valid_code  int                    null comment '0-Normal, 1-Signature verification failed, 2-Revoked, this field is not within the integrity verification scope, only for backend storage/viewing, all logic needs to recheck certificate status',
    constraint NAME
        unique (NAME)
);

create table IF NOT EXISTS t_cert_revoked_list
(
    id                  varchar(32) default '' not null comment 'Certificate ID, hash generated from certificate serial number, issuer, and user_id'
    primary key,
    issuer              varchar(255)           null comment 'Certificate issuer',
    serial_num          varchar(40)            null comment 'Certificate serial number',
    user_id             varchar(64)            null comment 'User ID',
    cert_revoked_date   bigint(1)              null comment 'Certificate revocation date',
    cert_revoked_reason varchar(32)            null comment 'Certificate revocation reason',
    signature           varbinary(512)         null comment 'Signature for integrity verification',
    key_version         varchar(36)            null comment 'Version of the key used for signing',
    key_id              varchar(128)           null comment 'ID of the key used for signing',
    valid_code          int                    null comment '0-Normal, 1-Signature verification failed, this field is not within the integrity verification scope, only for backend storage/viewing, all logic needs to recheck certificate status'
);

CREATE TABLE IF NOT EXISTS T_REF_VALUE
(
    id                  VARCHAR(32)     PRIMARY KEY COMMENT 'Baseline ID, hash generated from name, attester_type, and uid',
    uid                 VARCHAR(40)     NOT NULL    COMMENT 'User ID',
    name                VARCHAR(255)    NOT NULL    COMMENT 'Baseline name',
    version             INT             NOT NULL    COMMENT 'Baseline version',
    description         VARCHAR(1024)               COMMENT 'Baseline description',
    attester_type       VARCHAR(32)     NOT NULL    COMMENT 'Challenge plugin type',
    content             LONGTEXT        NOT NULL    COMMENT 'Baseline content',
    is_default          BOOL            NOT NULL    COMMENT 'Whether it is the default baseline',
    create_time         BIGINT          NOT NULL    COMMENT 'Creation time',
    update_time         BIGINT          NOT NULL    COMMENT 'Update time',
    signature           VARBINARY(512)              COMMENT 'Policy signature',
    key_version         VARCHAR(32)                 COMMENT 'Signature version',
    valid_code          INT                         COMMENT '0-Normal, 1-Signature verification failed, this field is not within the integrity verification scope, only for backend storage/viewing, all logic needs to recheck certificate status',
    unique (NAME)
);

CREATE TABLE IF NOT EXISTS T_REF_VALUE_DETAIL
(
    id                  VARCHAR(32)     PRIMARY KEY COMMENT 'Generated from filename and ref_value_id',
    uid                 VARCHAR(40)     NOT NULL    COMMENT 'User ID',
    attester_type       VARCHAR(32)     NOT NULL    COMMENT 'Challenge plugin type',
    file_name           VARCHAR(255)    NOT NULL    COMMENT 'Measurement file name',
    sha256              VARCHAR(64)     NOT NULL    COMMENT 'Measurement value',
    ref_value_id        VARCHAR(32)                 COMMENT 'Baseline ID'
);