import { CDPSession, Page } from '@playwright/test';

/**
 * A CDP virtual authenticator: platform, resident keys, user verification
 * always succeeds — what the plugin requires (UV + discoverable).
 */
export async function addVirtualAuthenticator(page: Page): Promise<{ cdp: CDPSession; authenticatorId: string }> {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
            protocol: 'ctap2',
            transport: 'internal',
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true,
        },
    });

    return { cdp, authenticatorId };
}

export async function credentialCount(cdp: CDPSession, authenticatorId: string): Promise<number> {
    const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });

    return credentials.length;
}
