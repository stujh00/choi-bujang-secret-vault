const deviceStatus = document.querySelector('#deviceStatus');
const installStatus = document.querySelector('#installStatus');
const installButton = document.querySelector('#installAppButton');
const connectionStatus = document.querySelector('#connectionStatus');
let installPrompt = null;

export function showDeviceStatus(serverSession) {
  // Only a server response may supply registration status; installation events never do.
  const device = serverSession?.device;
  if (serverSession?.user && device?.registered === true && device?.source === 'server') {
    deviceStatus.textContent = '서버에서 등록 기기로 확인했습니다.';
    deviceStatus.className = 'status success';
  } else {
    deviceStatus.textContent = serverSession?.user
      ? ({pending:'기기 승인 대기 · 운영자 확인 후 상태 확인을 눌러 주세요.',rejected:'기기 승인 거부',revoked:'기기 승인이 회수되었습니다.',expired:'기기 승인 기간이 만료되었습니다.'}[device?.status]
        ?? '기기 확인 미완료 · 이 기기의 승인을 요청해 주세요.')
      : '기기 확인 전 · 먼저 로그인해 주세요.';
    deviceStatus.className = 'status info';
  }
}
function showInstallStatus() {
  const standalone = window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
  installStatus.textContent = standalone
    ? '앱 화면으로 실행 중 · 설치 여부는 기기 승인 증거가 아닙니다.'
    : '브라우저로 실행 중 · 지원하는 브라우저의 메뉴에서 앱을 설치할 수 있습니다.';
}
function showConnectionStatus() {
  connectionStatus.hidden = navigator.onLine;
  if (!navigator.onLine) {
    document.querySelector('#notePanel').hidden = true;
    document.querySelector('#notes').replaceChildren();
    document.querySelector('#noteForm').reset();
    deviceStatus.textContent = '오프라인 · 서버에서 기기 상태를 확인할 수 없습니다.';
    deviceStatus.className = 'status info';
  }
}
window.addEventListener('beforeinstallprompt', event => {
  event.preventDefault(); installPrompt = event; installButton.hidden = false;
});
installButton.addEventListener('click', async () => {
  if (!installPrompt) return;
  installButton.disabled = true;
  try { await installPrompt.prompt(); await installPrompt.userChoice; }
  finally { installPrompt = null; installButton.hidden = true; installButton.disabled = false; }
});
window.addEventListener('appinstalled', () => { installButton.hidden = true; showInstallStatus(); });
window.addEventListener('offline', showConnectionStatus);
window.addEventListener('online', () => { showConnectionStatus(); window.location.reload(); });
showInstallStatus(); showConnectionStatus();
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js', {scope:'/'}).catch(() => {
    installStatus.textContent = '오프라인 안내를 준비하지 못했습니다. 온라인 브라우저 화면은 계속 사용할 수 있습니다.';
  });
}
