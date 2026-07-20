class ApplicationMailbox < ActionMailbox::Base
  routing all: :mailroom
end
