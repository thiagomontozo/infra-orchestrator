import '@testing-library/jest-dom/vitest';
/** jsdom ships <dialog> without its modal methods, which every Modal mounts on. */
HTMLDialogElement.prototype.showModal??=function(this:HTMLDialogElement){this.open=true};
HTMLDialogElement.prototype.close??=function(this:HTMLDialogElement){this.open=false};
Element.prototype.scrollIntoView??=function(){};
