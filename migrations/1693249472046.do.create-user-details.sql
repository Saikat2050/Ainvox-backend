-- 1693249472046.do.create-user-details.sql

CREATE TABLE "userDetails" (
    "userId" SERIAL PRIMARY KEY,
    "name" VARCHAR(255) NOT NULL,
    "email" VARCHAR(255) NOT NULL,
    "mobile" VARCHAR(255) NULL,
    "password" VARCHAR(255) NOT NULL,
    "dob" VARCHAR(255) NULL,
    "address" VARCHAR(255) NULL,
    "city" VARCHAR(50) NULL,
    "state" VARCHAR(50) NULL,
    "country" VARCHAR(50) NULL,
    "postal" INT NULL,
    "lastActivatedOn" TIMESTAMPTZ NULL,
    "secrectCode" VARCHAR(255) NULL,
    "isVerified" BOOLEAN DEFAULT FALSE NOT NULL,
    "isActive" BOOLEAN DEFAULT TRUE NOT NULL,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ NULL,
    "deletedAt" TIMESTAMPTZ NULL,
    "createdBy" INT NOT NULL, 
    "updatedBy" INT NULL, 
    "deletedBy" INT NULL 
);