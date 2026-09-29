// Firestore security rules tests (run inside the emulator: npm run test:rules).
import { assertFails, assertSucceeds, initializeTestEnvironment } from '@firebase/rules-unit-testing'
import { deleteDoc, doc, getDoc, getDocs, collection, setDoc, updateDoc } from 'firebase/firestore'
import { readFileSync } from 'node:fs'
import { after, before, beforeEach, describe, it } from 'node:test'

let env

before(async () => {
  env = await initializeTestEnvironment({
    projectId: 'demo-qrguard',
    firestore: { rules: readFileSync(new URL('../firestore.rules', import.meta.url), 'utf8') },
  })
})
after(async () => env.cleanup())

beforeEach(async () => {
  await env.clearFirestore()
  // Seed data the way the backend (Admin SDK) would write it.
  await env.withSecurityRulesDisabled(async (ctx) => {
    const db = ctx.firestore()
    await setDoc(doc(db, 'users/alice'), { save_history: true, is_anonymous: false })
    await setDoc(doc(db, 'users/alice/scans/s1'), { risk_score: 80, risk_level: 'MALICIOUS' })
    await setDoc(doc(db, 'reports/r1'), { uid: 'alice', status: 'open' })
    await setDoc(doc(db, 'stats_daily/2026-09-29'), { total: 3 })
  })
})

const as = (uid) => env.authenticatedContext(uid).firestore()
const anon = () => env.unauthenticatedContext().firestore()

describe('users and their scans', () => {
  it('the owner can read and delete their own history', async () => {
    await assertSucceeds(getDoc(doc(as('alice'), 'users/alice/scans/s1')))
    await assertSucceeds(getDocs(collection(as('alice'), 'users/alice/scans')))
    await assertSucceeds(deleteDoc(doc(as('alice'), 'users/alice/scans/s1')))
  })

  it('nobody else can read or delete it', async () => {
    await assertFails(getDoc(doc(anon(), 'users/alice/scans/s1')))
    await assertFails(getDoc(doc(as('bob'), 'users/alice/scans/s1')))
    await assertFails(getDocs(collection(as('bob'), 'users/alice/scans')))
    await assertFails(deleteDoc(doc(as('bob'), 'users/alice/scans/s1')))
  })

  it('clients cannot forge or change a verdict, even their own', async () => {
    await assertFails(setDoc(doc(as('alice'), 'users/alice/scans/fake'), { risk_score: 0, risk_level: 'SAFE' }))
    await assertFails(updateDoc(doc(as('alice'), 'users/alice/scans/s1'), { risk_score: 0 }))
  })

  it('the owner may only change their settings fields', async () => {
    await assertSucceeds(updateDoc(doc(as('alice'), 'users/alice'), { save_history: false }))
    await assertFails(updateDoc(doc(as('alice'), 'users/alice'), { admin: true }))
    await assertFails(updateDoc(doc(as('alice'), 'users/alice'), { save_history: 'yes' }))
    await assertFails(setDoc(doc(as('bob'), 'users/alice'), { save_history: false }))
    await assertFails(deleteDoc(doc(as('alice'), 'users/alice')))
  })
})

describe('server-only collections', () => {
  for (const path of ['reports/r1', 'stats_daily/2026-09-29', 'anything/else']) {
    it(`${path} is closed to clients`, async () => {
      await assertFails(getDoc(doc(as('alice'), path)))
      await assertFails(setDoc(doc(as('alice'), path), { x: 1 }))
      await assertFails(getDoc(doc(anon(), path)))
    })
  }
})
