import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';

import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('api');
  app.enableCors({ origin: process.env.ALLOW_CORS.split(',') });
  app.useGlobalPipes(new ValidationPipe());
  const swaggerConfig = new DocumentBuilder()
    .setTitle('Ace of Bids')
    .setDescription('Ace of Bids API description')
    .setVersion(`${process.env.npm_package_version}`)
    .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'Token' })
    .build();
  const swaggerDocument = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api', app, swaggerDocument);
  await app.listen(3000);
}
bootstrap();
