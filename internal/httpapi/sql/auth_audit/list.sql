SELECT event, user_id, username, client_ip, success, reason, created_at
FROM auth_audit_logs
/*%where */
/*%if present(Event) */
  AND event = /* Event */''
/*%end */
/*%if present(UserID) */
  AND user_id = /* UserID */''
/*%end */
/*%if present(UsernameLike) */
  AND username LIKE /* UsernameLike */''
/*%end */
/*%if present(ClientIPLike) */
  AND client_ip LIKE /* ClientIPLike */''
/*%end */
/*%if present(From) */
  AND created_at >= /* From */0
/*%end */
/*%if present(To) */
  AND created_at <= /* To */0
/*%end */
/*%end */
ORDER BY created_at DESC
LIMIT /* Limit */20 OFFSET /* Offset */0
