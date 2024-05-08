import { ForbiddenException, Injectable } from "@nestjs/common";
import { User, Bookmark, Prisma } from "@prisma/client";
import { PrismaService } from "src/prisma/prisma.service";
import * as argon from 'argon2';
import { AuthDto } from "src/dto";
import { instanceToInstance } from "class-transformer";
import { JwtService } from "@nestjs/jwt";

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService, 
        private jwt: JwtService
    ) {}

    async signup (dto: AuthDto) {
        const hash = await argon.hash(dto.password)
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash
                },
            })
    
            delete user.hash;
    
            return user;
        }
        catch (error) {
            if (error instanceof Prisma.PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Email already exists');
                }
            }
        }
    }

    async signin (dto: AuthDto) {
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email
            }
        })

        if (!user) {
            throw new ForbiddenException('Invalid email or password');
        }

        const match = await argon.verify(user.hash, dto.password);
        if (!match) {
            throw new ForbiddenException('Invalid email or password');
        }

        return this.signToken(user.id, user.email);
    }

    async signToken(userId: number, email: string): Promise<{access_token : string}> {
        const payload = { 
            sub: userId, 
            email
        };

        const token = await this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: process.env.JWT_SECRET
        });

        return {
            'access_token': token
        }
    }
}