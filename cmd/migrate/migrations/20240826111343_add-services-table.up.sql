CREATE TABLE IF NOT EXISTS services (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `service_name` VARCHAR(255) NOT NULL,
    `availability` TINYINT(1),
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY (service_name)
);


