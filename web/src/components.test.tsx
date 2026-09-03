import {describe,it,expect} from 'vitest';
import {render,screen,cleanup} from '@testing-library/react';
import {afterEach} from 'vitest';
import {Badge,Empty,ErrorBox} from './components';
afterEach(cleanup);
describe('operational states',()=>{it('shows empty data honestly',()=>{render(<Empty title="Nenhuma operação">Execute uma descoberta.</Empty>);expect(screen.getByText('Nenhuma operação')).toBeInTheDocument()});it('escapes untrusted state output',()=>{render(<Badge value={'<script>alert(1)</script>'}/>);expect(document.querySelector('script')).toBeNull()});it('announces backend failures',()=>{render(<ErrorBox error="MFA required"/>);expect(screen.getByRole('alert')).toHaveTextContent('MFA required')})});
