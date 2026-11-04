// Package recorder captures raw browser events (navigation, clicks, input, keys) in a visible
// Chromium on the user's machine. It only collects: turning the events into check steps happens
// on the server (import job "checks-record"), so no step or selector logic ships in the CLI.
package recorder

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// Element is what the page reports about the element an event hit.
type Element struct {
	Tag       string `json:"tag"`
	ID        string `json:"id"`
	TestID    string `json:"testid"`
	AriaLabel string `json:"aria"`
	Path      string `json:"path"`
	Password  bool   `json:"password"`
}

// Event is one user action seen in the page (type navigate, click, input or key).
type Event struct {
	Type  string  `json:"type"`
	URL   string  `json:"url"`
	El    Element `json:"el"`
	Value string  `json:"value"`
	Key   string  `json:"key"`
}

// recorderJS reports clicks, input changes and keys to the wtRecord binding.
const recorderJS = `(()=>{
const send=(o)=>{try{window.wtRecord(JSON.stringify(o))}catch(_){}};
const path=(e)=>{const parts=[];let n=e;
 while(n&&n.nodeType===1){let p=n.tagName.toLowerCase();
  if(n.id&&document.querySelectorAll('#'+CSS.escape(n.id)).length===1){parts.unshift('#'+CSS.escape(n.id));break}
  const sib=[...n.parentNode.children].filter(c=>c.tagName===n.tagName);
  if(sib.length>1)p+=':nth-of-type('+(sib.indexOf(n)+1)+')';
  parts.unshift(p);const q=parts.join(' > ');
  try{if(document.querySelectorAll(q).length===1)return q}catch(_){}
  n=n.parentElement}
 return parts.join(' > ')};
const el=(e)=>({tag:e.tagName.toLowerCase(),id:e.id||'',testid:e.getAttribute('data-testid')||'',aria:e.getAttribute('aria-label')||'',path:path(e),password:e.type==='password'});
addEventListener('click',e=>send({type:'click',el:el(e.target.closest('a,button,input,select,[role]')||e.target)}),true);
addEventListener('change',e=>send({type:'input',el:el(e.target),value:e.target.value}),true);
addEventListener('keydown',e=>{if(['Enter','Tab','Escape'].includes(e.key))send({type:'key',key:e.key})},true);
send({type:'navigate',url:location.href});
})()`

// Record opens a visible Chromium on startURL and returns the events when ctx ends (Ctrl+C in
// wtctl). Values typed into password fields are dropped here.
func Record(ctx context.Context, startURL, execPath string) ([]Event, error) {
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts, chromedp.Flag("headless", false), chromedp.WindowSize(1280, 800))
	if execPath != "" {
		opts = append(opts, chromedp.ExecPath(execPath))
	}
	actx, cancelA := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelA()
	bctx, cancelB := chromedp.NewContext(actx)
	defer cancelB()
	var (
		mu     sync.Mutex
		events []Event
	)
	chromedp.ListenTarget(bctx, func(ev any) {
		e, ok := ev.(*runtime.EventBindingCalled)
		if !ok || e.Name != "wtRecord" {
			return
		}
		r, ok := parseEvent(e.Payload)
		if !ok {
			return
		}
		mu.Lock()
		events = append(events, r)
		mu.Unlock()
	})
	err := chromedp.Run(bctx,
		runtime.Enable(),
		runtime.AddBinding("wtRecord"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(recorderJS).Do(ctx)
			return err
		}),
		chromedp.Navigate(startURL),
	)
	if err != nil && ctx.Err() == nil {
		return nil, err
	}
	<-ctx.Done()
	mu.Lock()
	defer mu.Unlock()
	return events, nil
}

// parseEvent decodes one page report. Values typed into password fields are dropped here, so a
// password never leaves the machine (the server writes {{secret.PASSWORD}} in its place).
func parseEvent(payload string) (Event, bool) {
	var r Event
	if json.Unmarshal([]byte(payload), &r) != nil {
		return Event{}, false
	}
	if r.El.Password {
		r.Value = ""
	}
	return r, true
}
