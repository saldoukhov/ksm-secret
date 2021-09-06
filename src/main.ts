import * as core from '@actions/core'
import * as github from '@actions/github'
import * as sodium from 'tweetsodium'
import {getSecrets, initializeStorage, inMemoryStorage} from '@keeper-security/secrets-manager-core'

async function run(): Promise<void> {
    try {
        // Prepare Github communications
        const pa_token = core.getInput('accessToken')
        core.getInput('accessToken')
        const octokit = github.getOctokit(pa_token)
        const getPublicKey = octokit.rest.actions['getRepoPublicKey']
        const upsertSecret = octokit.rest.actions['createOrUpdateRepoSecret']

        // Convert one time token to KSM config
        const hostAndToken = core.getInput('oneTimeToken').split(':')
        const ksmConfig = {}
        const storage = inMemoryStorage(ksmConfig)
        await initializeStorage(storage, hostAndToken[1], hostAndToken[0]) // Initialize the config with the private key
        await getSecrets({storage}) // Get the secrets once so the client is bound to the private key
        const secret = JSON.stringify(ksmConfig)

        // Save the config to the repository
        const {data: public_key} = await getPublicKey(github.context.repo)
        const publicKeyBytes = Buffer.from(public_key.key, 'base64')
        const secretBytes = sodium.seal(Buffer.from(secret), publicKeyBytes)
        const secretValue = Buffer.from(secretBytes).toString('base64')
        const {status} = await upsertSecret({
            ...github.context.repo,
            secret_name: core.getInput('configName'),
            encrypted_value: secretValue,
            key_id: public_key.key_id
        })
    } catch (error) {
        core.setFailed(error.message)
    }
}

run()
