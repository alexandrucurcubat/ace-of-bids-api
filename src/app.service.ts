import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  api(): string {
    return `Ace of Bids API v(${process.env.npm_package_version})`;
  }
}
