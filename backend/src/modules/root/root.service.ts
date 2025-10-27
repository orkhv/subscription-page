import { RawAxiosResponseHeaders } from 'axios';
import { AxiosResponseHeaders } from 'axios';
import { Request, Response } from 'express';
import { createHash } from 'node:crypto';
import { nanoid } from 'nanoid';
import { promises as fs } from 'node:fs';

import { ConfigService } from '@nestjs/config';
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Logger } from '@nestjs/common';

import { TRequestTemplateTypeKeys } from '@remnawave/backend-contract';

import { AxiosService } from '@common/axios/axios.service';
import { sanitizeUsername } from '@common/utils';

@Injectable()
export class RootService {
    private readonly logger = new Logger(RootService.name);

    private readonly isMarzbanLegacyLinkEnabled: boolean;
    private readonly marzbanSecretKey?: string;
    private defaultJsonCache: any[] | null = null;
    private loadDefaultJsonPromise: Promise<any[]> | null = null;
    private defaultJsonMtime: number = 0;

    constructor(
        private readonly configService: ConfigService,
        private readonly jwtService: JwtService,
        private readonly axiosService: AxiosService,
    ) {
        this.isMarzbanLegacyLinkEnabled = this.configService.getOrThrow<boolean>(
            'MARZBAN_LEGACY_LINK_ENABLED',
        );
        this.marzbanSecretKey = this.configService.get<string>('MARZBAN_LEGACY_SECRET_KEY');
    }

    public async serveSubscriptionPage(
        clientIp: string,
        req: Request,
        res: Response,
        shortUuid: string,
        clientType?: TRequestTemplateTypeKeys,
    ): Promise<void> {
        try {
            const userAgent = req.headers['user-agent'];

            let shortUuidLocal = shortUuid;

            if (this.isGenericPath(req.path)) {
                res.socket?.destroy();
                return;
            }

            if (this.isMarzbanLegacyLinkEnabled) {
                const username = await this.decodeMarzbanLink(shortUuid);

                if (username) {
                    const sanitizedUsername = sanitizeUsername(username.username);

                    this.logger.log(
                        `Decoded Marzban username: ${username.username}, sanitized username: ${sanitizedUsername}`,
                    );

                    const userInfo = await this.axiosService.getUserByUsername(
                        clientIp,
                        sanitizedUsername,
                    );
                    if (!userInfo.isOk || !userInfo.response) {
                        this.logger.error(
                            `Decoded Marzban username is not found in Remnawave, decoded username: ${sanitizedUsername}`,
                        );

                        res.socket?.destroy();
                        return;
                    }

                    shortUuidLocal = userInfo.response.response.shortUuid;
                }
            }

            // Обработка специальных клиентов (приложений): Happ, Streisand, v2rayng, v2box
            if (userAgent && this.isClientApp(userAgent)) {
                this.logger.debug(
                    `[ClientApp] UA matched, returning JSON from template. ua=${userAgent}, shortUuid=${shortUuidLocal}`,
                );
                return this.returnClientAppJson(clientIp, req, res, shortUuidLocal);
            }

            if (userAgent && this.isBrowser(userAgent)) {
                return this.returnWebpage(clientIp, req, res, shortUuidLocal);
            }

            let subscriptionDataResponse: {
                response: unknown;
                headers: RawAxiosResponseHeaders | AxiosResponseHeaders;
            } | null = null;

            subscriptionDataResponse = await this.axiosService.getSubscription(
                clientIp,
                shortUuidLocal,
                req.headers,
                !!clientType,
                clientType,
            );

            if (!subscriptionDataResponse) {
                res.socket?.destroy();
                return;
            }

            if (subscriptionDataResponse.headers) {
                Object.entries(subscriptionDataResponse.headers)
                    .filter(([key]) => {
                        const ignoredHeaders = ['transfer-encoding', 'content-length', 'server'];
                        return !ignoredHeaders.includes(key.toLowerCase());
                    })
                    .forEach(([key, value]) => {
                        res.setHeader(key, value);
                    });
            }

            res.status(200).send(subscriptionDataResponse.response);
        } catch (error) {
            this.logger.error('Error in serveSubscriptionPage', error);

            res.socket?.destroy();
            return;
        }
    }

    private async generateJwtForCookie(): Promise<string> {
        return this.jwtService.sign(
            {
                sessionId: nanoid(32),
            },
            {
                expiresIn: '1h',
            },
        );
    }

    private isBrowser(userAgent: string): boolean {
        const browserKeywords = [
            'Mozilla',
            'Chrome',
            'Safari',
            'Firefox',
            'Opera',
            'Edge',
            'TelegramBot',
        ];

        return browserKeywords.some((keyword) => userAgent.includes(keyword));
    }

    private isClientApp(userAgent: string): boolean {
        const ua = userAgent.toLowerCase();
        const appKeywords = ['happ', 'streisand', 'v2rayng', 'v2box'];
        return appKeywords.some((kw) => ua.includes(kw));
    }

    private isGenericPath(path: string): boolean {
        const genericPaths = ['favicon.ico', 'robots.txt'];

        return genericPaths.some((genericPath) => path.includes(genericPath));
    }

    private async returnWebpage(
        clientIp: string,
        req: Request,
        res: Response,
        shortUuid: string,
    ): Promise<void> {
        try {
            const cookieJwt = await this.generateJwtForCookie();

            const subscriptionDataResponse = await this.axiosService.getSubscriptionInfo(
                clientIp,
                shortUuid,
            );

            if (!subscriptionDataResponse.isOk) {
                this.logger.error(`Get subscription info failed, shortUuid: ${shortUuid}`);

                res.socket?.destroy();
                return;
            }

            const subscriptionData = subscriptionDataResponse.response;

            res.cookie('session', cookieJwt, {
                httpOnly: true,
                secure: true,
                maxAge: 3_600_000, // 1 hour
            });

            this.logger.debug('[Browser] Rendering subscription webpage (base64 panel data)');
            res.render('index', {
                metaTitle: this.configService
                    .getOrThrow<string>('META_TITLE')
                    .replace(/^"|"$/g, ''),
                metaDescription: this.configService
                    .getOrThrow<string>('META_DESCRIPTION')
                    .replace(/^"|"$/g, ''),
                panelData: Buffer.from(JSON.stringify(subscriptionData)).toString('base64'),
            });
        } catch (error) {
            this.logger.error('Error in returnWebpage', error);

            res.socket?.destroy();
            return;
        }
    }

    private async returnClientAppJson(
        clientIp: string,
        req: Request,
        res: Response,
        shortUuid: string,
    ): Promise<void> {
        try {
            this.logger.debug('[ClientApp] Fetching raw subscription with disabled hosts');
            const rawResponse = await this.axiosService.getSubscriptionRawWithDisabledHosts(
                clientIp,
                shortUuid,
                req.headers,
            );

            if (!rawResponse || !rawResponse.response) {
                this.logger.error(
                    `GetSubscriptionRawWithDisabledHosts failed, shortUuid: ${shortUuid}, hasHeaders: ${!!rawResponse?.headers}`,
                );
                res.socket?.destroy();
                return;
            }

            const body: any = rawResponse.response as any;
            const user = body?.response?.user;

            const username: string | undefined = user?.username;
            const vlessUuid: string | undefined = user?.vlessUuid;
            const ssPassword: string | undefined = user?.ssPassword;

            this.logger.debug(
                `[ClientApp] Extracted user fields: username=${username}, vlessUuid=${this.maskSecret(vlessUuid)}, ssPassword=${this.maskSecret(ssPassword)}`,
            );

            if (!username || !vlessUuid || !ssPassword) {
                this.logger.error(
                    `Required fields missing in raw response. username: ${username}, vlessUuid: ${vlessUuid}, ssPassword: ${!!ssPassword}`,
                );
                res.socket?.destroy();
                return;
            }

            const templateArray = await this.loadDefaultJsonArray();
            const transformed = this.transformDefaultJson(templateArray, {
                username,
                vlessUuid,
                ssPassword,
            });

            if (rawResponse.headers) {
                Object.entries(rawResponse.headers)
                    .filter(([key]) => {
                        const ignoredHeaders = ['transfer-encoding', 'content-length', 'server'];
                        return !ignoredHeaders.includes(key.toLowerCase());
                    })
                    .forEach(([key, value]) => {
                        res.setHeader(key, value as any);
                    });
            }

            // Дополнительно проксируем мета-заголовки из тела ответа панели (response.headers)
            const panelMetaHeaders: Record<string, string> | undefined = body?.response?.headers;
            if (panelMetaHeaders && typeof panelMetaHeaders === 'object') {
                Object.entries(panelMetaHeaders)
                    .filter(([key]) => {
                        const ignoredHeaders = ['transfer-encoding', 'content-length', 'server'];
                        return !ignoredHeaders.includes(key.toLowerCase());
                    })
                    .forEach(([key, value]) => {
                        try {
                            // Ставим мета-заголовок только если он ещё не был установлен из HTTP-ответа панели
                            if (!res.hasHeader(key)) {
                                res.setHeader(key, value);
                            }
                        } catch (_) {
                            // пропускаем некорректные ключи
                        }
                    });
            }

            this.logger.debug('[ClientApp] Sending transformed JSON response');
            res.status(200).json(transformed);
        } catch (error) {
            this.logger.error('Error in returnClientAppJson', error);
            res.socket?.destroy();
            return;
        }
    }

    private async loadDefaultJsonArray(): Promise<any[]> {
        const filePath = '/backend/default.json';
        
        // Если кэш есть, проверяем изменился ли файл
        if (this.defaultJsonCache) {
            try {
                const stats = await fs.stat(filePath);
                if (stats.mtimeMs > this.defaultJsonMtime) {
                    this.logger.log('[Template] default.json file modified, clearing cache');
                    this.defaultJsonCache = null;
                } else {
                    // Проверяем кэш еще раз перед возвратом, чтобы избежать race condition
                    if (this.defaultJsonCache) {
                        this.logger.debug('[Template] Using cached default.json');
                        return this.defaultJsonCache;
                    }
                }
            } catch (err) {
                this.logger.error(`Failed to check default.json mtime: ${err}`);
                // Возвращаем кэш, но не null - используем существующий кэш или выбрасываем ошибку
                if (this.defaultJsonCache) {
                    return this.defaultJsonCache;
                }
                throw err;
            }
        }

        // Если загрузка уже началась другим запросом, ждём её
        if (this.loadDefaultJsonPromise) {
            this.logger.debug('[Template] Waiting for ongoing load');
            return this.loadDefaultJsonPromise;
        }

        // Начинаем загрузку и сохраняем промис, чтобы другие запросы ждали
        this.loadDefaultJsonPromise = this.doLoadDefaultJsonArray();

        try {
            const result = await this.loadDefaultJsonPromise;
            return result;
        } finally {
            // Очищаем промис после завершения (успех или ошибка)
            this.loadDefaultJsonPromise = null;
        }
    }

    private async doLoadDefaultJsonArray(): Promise<any[]> {
        // Жёсткий путь внутри образа/контейнера
        const filePath = '/backend/default.json';
        const content = await fs.readFile(filePath, 'utf-8');
        const parsed = JSON.parse(content);

        if (!Array.isArray(parsed)) {
            throw new Error('default.json is not an array');
        }

        this.defaultJsonCache = parsed;
        
        // Сохраняем mtime для проверки изменений
        try {
            const stats = await fs.stat(filePath);
            this.defaultJsonMtime = stats.mtimeMs;
        } catch (err) {
            this.logger.error(`Failed to get default.json mtime: ${err}`);
        }
        
        this.logger.log(`[Template] Loaded /backend/default.json profiles=${parsed.length}`);
        return this.defaultJsonCache;
    }

    private transformDefaultJson(
        templateArray: any[],
        creds: { username: string; vlessUuid: string; ssPassword: string },
    ): any[] {
        // Глубокое копирование, чтобы не мутировать исходник
        const clone = JSON.parse(JSON.stringify(templateArray));

        for (const profile of clone) {
            // Обновить remarks на верхнем уровне, если это профиль с "ID: "
            if (typeof profile?.remarks === 'string') {
                if (profile.remarks.trim() === 'ID:' || profile.remarks === 'ID: ') {
                    profile.remarks = `ID: ${creds.username}`;
                }
            }

            const outbounds = profile?.outbounds;
            if (!Array.isArray(outbounds)) continue;

            for (const outbound of outbounds) {
                if (!outbound || typeof outbound !== 'object') continue;

                const protocol = outbound.protocol;
                const settings = outbound.settings;

                if (!settings || typeof settings !== 'object') continue;

                if (protocol === 'vless') {
                    const vnext = settings.vnext;
                    if (Array.isArray(vnext)) {
                        for (const vn of vnext) {
                            const users = vn?.users;
                            if (Array.isArray(users)) {
                                for (const user of users) {
                                    if (user && typeof user === 'object') {
                                        user.id = creds.vlessUuid;
                                    }
                                }
                            }
                        }
                    }
                }

                if (protocol === 'shadowsocks') {
                    const servers = settings.servers;
                    if (Array.isArray(servers)) {
                        for (const srv of servers) {
                            if (srv && typeof srv === 'object') {
                                srv.password = creds.ssPassword;
                            }
                        }
                    }
                }
            }
        }

        return clone;
    }

    private maskSecret(value?: string): string {
        if (!value) return 'null';
        if (value.length <= 8) return '****';
        return `${value.slice(0, 4)}…${value.slice(-4)}`;
    }


    private async decodeMarzbanLink(shortUuid: string): Promise<{
        username: string;
        createdAt: Date;
    } | null> {
        const token = shortUuid;
        this.logger.debug(`Verifying token: ${token}`);

        if (!token || token.length < 10) {
            this.logger.debug(`Token too short: ${token}`);
            return null;
        }

        if (token.split('.').length === 3) {
            try {
                const payload = await this.jwtService.verifyAsync(token, {
                    secret: this.marzbanSecretKey!,
                    algorithms: ['HS256'],
                });

                if (payload.access !== 'subscription') {
                    throw new Error('JWT access field is not subscription');
                }

                const jwtCreatedAt = new Date(payload.iat * 1000);

                if (!this.checkSubscriptionValidity(jwtCreatedAt, payload.sub)) {
                    return null;
                }

                this.logger.debug(`JWT verified successfully, ${JSON.stringify(payload)}`);

                return {
                    username: payload.sub,
                    createdAt: jwtCreatedAt,
                };
            } catch (err) {
                this.logger.debug(`JWT verification failed: ${err}`);
            }
        }

        const uToken = token.slice(0, token.length - 10);
        const uSignature = token.slice(token.length - 10);

        this.logger.debug(`Token parts: base: ${uToken}, signature: ${uSignature}`);

        let decoded: string;
        try {
            decoded = Buffer.from(uToken, 'base64url').toString();
        } catch (err) {
            this.logger.debug(`Base64 decode error: ${err}`);
            return null;
        }

        const hash = createHash('sha256');
        hash.update(uToken + this.marzbanSecretKey!);
        const digest = hash.digest();

        const expectedSignature = Buffer.from(digest).toString('base64url').slice(0, 10);

        this.logger.debug(`Expected signature: ${expectedSignature}, actual: ${uSignature}`);

        if (uSignature !== expectedSignature) {
            this.logger.debug('Signature mismatch');
            return null;
        }

        const parts = decoded.split(',');
        if (parts.length < 2) {
            this.logger.debug(`Invalid token format: ${decoded}`);
            return null;
        }

        const username = parts[0];
        const createdAtInt = parseInt(parts[1], 10);

        if (isNaN(createdAtInt)) {
            this.logger.debug(`Invalid created_at timestamp: ${parts[1]}`);
            return null;
        }

        const createdAt = new Date(createdAtInt * 1000);

        if (!this.checkSubscriptionValidity(createdAt, username)) {
            return null;
        }

        this.logger.debug(`Token decoded. Username: ${username}, createdAt: ${createdAt}`);

        return {
            username,
            createdAt,
        };
    }

    private checkSubscriptionValidity(createdAt: Date, username: string): boolean {
        const validFrom = this.configService.get<string | undefined>(
            'MARZBAN_LEGACY_SUBSCRIPTION_VALID_FROM',
        );

        if (!validFrom) {
            return true;
        }

        const validFromDate = new Date(validFrom);
        if (createdAt < validFromDate) {
            this.logger.debug(
                `createdAt JWT: ${createdAt.toISOString()} is before validFrom: ${validFromDate.toISOString()}`,
            );

            this.logger.warn(
                `${JSON.stringify({ username, createdAt })} – subscription createdAt is before validFrom`,
            );

            return false;
        }

        return true;
    }
}
