import { RawAxiosResponseHeaders } from 'axios';
import { AxiosResponseHeaders } from 'axios';
import { Request, Response } from 'express';
import { createHash } from 'node:crypto';
import { nanoid } from 'nanoid';

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
    private readonly subscriptionUiDisplayRawKeys: boolean;

    constructor(
        private readonly configService: ConfigService,
        private readonly jwtService: JwtService,
        private readonly axiosService: AxiosService,
    ) {
        this.isMarzbanLegacyLinkEnabled = this.configService.getOrThrow<boolean>(
            'MARZBAN_LEGACY_LINK_ENABLED',
        );
        this.marzbanSecretKey = this.configService.get<string>('MARZBAN_LEGACY_SECRET_KEY');
        this.subscriptionUiDisplayRawKeys = this.configService.getOrThrow<boolean>(
            'SUBSCRIPTION_UI_DISPLAY_RAW_KEYS',
        );
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

            // Получаем данные пользователя для подстановки ssPassword и vlessUuid
            let userInfo;
            try {
                userInfo = await this.axiosService.getUserByShortUuid(
                    clientIp,
                    shortUuidLocal,
                );
            } catch (error) {
                this.logger.warn(
                    `Failed to get user info for shortUuid: ${shortUuidLocal}, continuing without credential substitution`,
                    error,
                );
                userInfo = { isOk: false };
            }

            let responseData = subscriptionDataResponse.response;

            // Если получили данные пользователя и response является массивом (конфигурация xray)
            if (
                userInfo.isOk &&
                userInfo.response &&
                userInfo.response.response &&
                Array.isArray(responseData)
            ) {
                const ssPassword = userInfo.response.response.ssPassword;
                const vlessUuid = userInfo.response.response.vlessUuid;

                // Проверяем, что ssPassword и vlessUuid существуют и являются строками
                if (
                    typeof ssPassword === 'string' &&
                    ssPassword.length > 0 &&
                    typeof vlessUuid === 'string' &&
                    vlessUuid.length > 0
                ) {
                    responseData = this.fillEmptyCredentials(responseData, ssPassword, vlessUuid);
                } else {
                    this.logger.warn(
                        `Invalid ssPassword or vlessUuid for shortUuid: ${shortUuidLocal}. ssPassword: ${typeof ssPassword}, vlessUuid: ${typeof vlessUuid}`,
                    );
                }
            } else if (Array.isArray(responseData)) {
                // Логируем, если не удалось получить данные пользователя, но конфигурация является массивом
                this.logger.debug(
                    `Skipping credential substitution for shortUuid: ${shortUuidLocal}. userInfo.isOk: ${userInfo.isOk}`,
                );
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

            res.status(200).send(responseData);
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
            'WhatsApp',
        ];

        return browserKeywords.some((keyword) => userAgent.includes(keyword));
    }

    private isGenericPath(path: string): boolean {
        const genericPaths = [
            'favicon.ico',
            'robots.txt',
            '.png',
            '.jpg',
            '.jpeg',
            '.gif',
            '.svg',
            '.webp',
            '.ico',
        ];

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

            if (!subscriptionDataResponse.isOk || !subscriptionDataResponse.response) {
                this.logger.error(`Get subscription info failed, shortUuid: ${shortUuid}`);

                res.socket?.destroy();
                return;
            }

            const subscriptionData = subscriptionDataResponse.response;

            if (!this.subscriptionUiDisplayRawKeys) {
                subscriptionData.response.links = [];
                subscriptionData.response.ssConfLinks = {};
            }

            res.cookie('session', cookieJwt, {
                httpOnly: true,
                secure: true,
                maxAge: 3_600_000, // 1 hour
            });

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

    private fillEmptyCredentials(
        configArray: unknown[],
        ssPassword: string,
        vlessUuid: string,
    ): unknown[] {
        return configArray.map((config) => {
            if (typeof config !== 'object' || config === null) {
                return config;
            }

            const configObj = config as Record<string, unknown>;

            if (!configObj.outbounds || !Array.isArray(configObj.outbounds)) {
                return config;
            }

            const modifiedConfig = { ...configObj };
            modifiedConfig.outbounds = configObj.outbounds.map((outbound: unknown) => {
                if (typeof outbound !== 'object' || outbound === null) {
                    return outbound;
                }

                const outboundObj = outbound as Record<string, unknown>;
                let modifiedOutbound: Record<string, unknown> | null = null;

                // Обработка shadowsocks
                if (outboundObj.protocol === 'shadowsocks' && outboundObj.settings) {
                    const settings = outboundObj.settings as Record<string, unknown>;
                    if (typeof settings === 'object' && settings !== null && Array.isArray(settings.servers)) {
                        const hasEmptyPassword = settings.servers.some((server: unknown) => {
                            if (typeof server !== 'object' || server === null) {
                                return false;
                            }
                            const serverObj = server as Record<string, unknown>;
                            const password = serverObj.password;
                            return (
                                password === '' ||
                                password === ' ' ||
                                password === null ||
                                password === undefined
                            );
                        });

                        if (hasEmptyPassword) {
                            modifiedOutbound = { ...outboundObj };
                            modifiedOutbound.settings = {
                                ...settings,
                                servers: settings.servers.map((server: unknown) => {
                                    if (typeof server !== 'object' || server === null) {
                                        return server;
                                    }

                                    const serverObj = server as Record<string, unknown>;
                                    const password = serverObj.password;

                                    // Проверяем, пустой ли password ("" или " ")
                                    if (
                                        password === '' ||
                                        password === ' ' ||
                                        password === null ||
                                        password === undefined
                                    ) {
                                        return {
                                            ...serverObj,
                                            password: ssPassword,
                                        };
                                    }

                                    return { ...serverObj };
                                }),
                            };
                        }
                    }
                }

                // Обработка vless
                if (outboundObj.protocol === 'vless' && outboundObj.settings) {
                    const settings = outboundObj.settings as Record<string, unknown>;
                    if (typeof settings === 'object' && settings !== null && Array.isArray(settings.vnext)) {
                        const hasEmptyId = settings.vnext.some((vnextItem: unknown) => {
                            if (typeof vnextItem !== 'object' || vnextItem === null) {
                                return false;
                            }
                            const vnextObj = vnextItem as Record<string, unknown>;
                            if (!Array.isArray(vnextObj.users)) {
                                return false;
                            }
                            return vnextObj.users.some((user: unknown) => {
                                if (typeof user !== 'object' || user === null) {
                                    return false;
                                }
                                const userObj = user as Record<string, unknown>;
                                const id = userObj.id;
                                return (
                                    id === '' ||
                                    id === ' ' ||
                                    id === null ||
                                    id === undefined
                                );
                            });
                        });

                        if (hasEmptyId) {
                            if (!modifiedOutbound) {
                                modifiedOutbound = { ...outboundObj };
                            }
                            modifiedOutbound.settings = {
                                ...settings,
                                vnext: settings.vnext.map((vnextItem: unknown) => {
                                    if (typeof vnextItem !== 'object' || vnextItem === null) {
                                        return vnextItem;
                                    }

                                    const vnextObj = vnextItem as Record<string, unknown>;
                                    if (Array.isArray(vnextObj.users)) {
                                        return {
                                            ...vnextObj,
                                            users: vnextObj.users.map((user: unknown) => {
                                                if (typeof user !== 'object' || user === null) {
                                                    return user;
                                                }

                                                const userObj = user as Record<string, unknown>;
                                                const id = userObj.id;

                                                // Проверяем, пустой ли id ("" или " ")
                                                if (
                                                    id === '' ||
                                                    id === ' ' ||
                                                    id === null ||
                                                    id === undefined
                                                ) {
                                                    return {
                                                        ...userObj,
                                                        id: vlessUuid,
                                                    };
                                                }

                                                return { ...userObj };
                                            }),
                                        };
                                    }

                                    return { ...vnextObj };
                                }),
                            };
                        }
                    }
                }

                return modifiedOutbound || { ...outboundObj };
            });

            return modifiedConfig;
        });
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
