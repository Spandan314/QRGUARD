import { render, screen } from '@testing-library/react-native'
import { BRAND_MARK_SVG } from '../constants/brandMark'
import { BrandTitle } from './BrandTitle'

test('the header shows the QRGUARD wordmark as a heading', async () => {
  await render(<BrandTitle />)
  expect(screen.getByRole('header')).toHaveTextContent('QRGUARD')
})

test('the generated mark is a self-contained SVG', () => {
  expect(BRAND_MARK_SVG).toMatch(/^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 120 120">/)
  expect(BRAND_MARK_SVG).not.toMatch(/https?:\/\/(?!www\.w3\.org)|<script|<image/)
})
