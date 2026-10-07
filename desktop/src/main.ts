import { mount } from 'svelte';
import App from './Root.svelte';
import './style.css';
mount(App, { target: document.getElementById('app')! });
