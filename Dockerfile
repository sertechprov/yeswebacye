# Use an official PHP runtime as a parent image
FROM php:8.1-apache

# Set working directory
WORKDIR /var/www/html

# Copy the current directory contents into the container at /var/www/html
COPY . /var/www/html

# Install PHP extensions if needed (optional, adjust based on your app requirements)
# Example:
# RUN docker-php-ext-install mysqli pdo pdo_mysql

# Expose port 80 to the outside world
EXPOSE 80
