SELECT extname, extrelocatable 
FROM pg_extension 
WHERE extname LIKE 'pgaudit%'
ORDER BY extname;