-- Create a user as root and grant permissions
CREATE USER IF NOT EXISTS 'abcd'@'%' IDENTIFIED WITH mysql_native_password BY 'abcd';
GRANT ALL PRIVILEGES ON *.* TO 'abcd'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;