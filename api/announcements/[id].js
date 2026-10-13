import { handleAnnouncement } from '../../src/announcement-api.mjs';
export default (request, response) => handleAnnouncement(request, response, 'item');
