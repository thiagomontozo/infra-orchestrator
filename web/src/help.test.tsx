import {describe,it,expect,afterEach} from 'vitest';
import {render,screen,cleanup,fireEvent} from '@testing-library/react';
import {Help,topics} from './help';
afterEach(cleanup);
describe('central de ajuda',()=>{
 it('opens on the topic of the current page',()=>{render(<Help page="approvals" close={()=>{}} navigate={()=>{}}/>);expect(screen.getByRole('heading',{level:3})).toHaveTextContent('Operações e aprovações')});
 it('falls back to the first topic for an unknown page',()=>{render(<Help page="inexistente" close={()=>{}} navigate={()=>{}}/>);expect(screen.getByRole('heading',{level:3})).toHaveTextContent('Primeiros passos')});
 it('searches the body of every topic, not only titles',()=>{render(<Help page="dashboard" close={()=>{}} navigate={()=>{}}/>);fireEvent.change(screen.getByLabelText('Buscar na ajuda'),{target:{value:'fingerprint'}});expect(screen.getByRole('heading',{level:3})).toHaveTextContent('Hosts, bastions e grupos')});
 it('reports honestly when nothing matches',()=>{render(<Help page="dashboard" close={()=>{}} navigate={()=>{}}/>);fireEvent.change(screen.getByLabelText('Buscar na ajuda'),{target:{value:'zzzz'}});expect(screen.getByText('Nenhum assunto encontrado')).toBeInTheDocument()});
 it('navigates to the page a topic documents',()=>{let target='';render(<Help page="hosts" close={()=>{}} navigate={p=>{target=p}}/>);fireEvent.click(screen.getByText('Abrir a página'));expect(target).toBe('hosts')});
 it('keeps topic ids unique',()=>{expect(new Set(topics.map(t=>t.id)).size).toBe(topics.length)});
});
