FROM php:8.2-cli

# Install zip extension and other requirements
RUN apt-get update && apt-get install -y \
    git \
    unzip \
    && docker-php-ext-install bcmath

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /app

# Create directory structure and copy files
COPY . .