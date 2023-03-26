CREATE TABLE boilerplate.member
(
    id                  BIGINT          NOT NULL AUTO_INCREMENT,
    username            VARCHAR(255)    NOT NULL comment '유저 계정',
    password            VARCHAR(255)    NOT NULL comment '패스워드',
    token               VARCHAR(255)    NOT NULL comment '리프레쉬 토큰',
    profile_name        VARCHAR(255)    NOT NULL comment '유저 닉네임',
    role_list_string    VARCHAR(255)    NOT NULL comment '유저 권한 목록',
    date_created        DATETIME        NOT NULL comment '생성일자',
    date_updated        DATETIME        NOT NULL comment '수정일자',
    auditor             VARCHAR(100)    NOT NULL comment '수정자',
    PRIMARY KEY (`id`),
    UNIQUE  username (`username`)
) ENGINE=InnoDB
    DEFAULT CHARSET=utf8mb4
    comment='회원 테이블';

CREATE TABLE boilerplate.role (
    id          BIGINT          NOT NULL AUTO_INCREMENT,
    role_type   VARCHAR(255)    NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE  role_type (`role_type`)
) ENGINE=InnoDB
    DEFAULT CHARSET=utf8mb4
    comment='권한 테이블';



INSERT IGNORE INTO boilerplate.role(role_type)
VALUES  ('ROLE_USER'),
        ('ROLE_ADMIN')
;