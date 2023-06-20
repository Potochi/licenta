FROM php:7.2-apache

# Copy the PHP script to the document root
COPY ./hello.php /var/www/html/hello.php

# Apache configuration to route /hello to /hello.php
RUN echo '<Location "/hello">\n\
  RewriteEngine On\n\
  RewriteRule .* /hello.php [L]\n\
  </Location>' > /etc/apache2/conf-available/rewrite.conf && \
  a2enmod rewrite && a2enconf rewrite

EXPOSE 80

