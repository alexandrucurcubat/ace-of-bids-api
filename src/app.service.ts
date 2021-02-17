import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  api(): string {
    return `Ace of Bids API v(0.0.1)`;
  }
}
