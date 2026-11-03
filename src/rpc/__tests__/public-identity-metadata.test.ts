import {describe,it,expect} from 'vitest';
import {normalizeMetadata} from '../public-identity-metadata';
describe('browser identity metadata',()=>{
    it.each([true,false])('derives setup policy from stored boolean %s without modifying it',required=>{
        const source={must_change_password:required,first_login_setup_required:!required,portal_mode:'assigned_trainer',nested:[{refresh_token:'secret-value',department:'MBA'}]};
        expect(normalizeMetadata(source)).toEqual({first_login_setup_required:required,portal_mode:'assigned_trainer',nested:[{department:'MBA'}]});
        expect(source.must_change_password).toBe(required);expect(source.nested[0].refresh_token).toBe('secret-value');
    });
    it('ignores a supplied setup alias without an authoritative flag',()=>{expect(normalizeMetadata({first_login_setup_required:true})).toEqual({});});
    it('keeps absent metadata absent',()=>{expect(normalizeMetadata(undefined)).toBeUndefined();});
});
