require 'active_record'
require 'unix_crypt'
require 'bcrypt'
require 'phpass'

class CASino::ActiveRecordAuthenticator
  class AuthDatabase < ::ActiveRecord::Base
    self.abstract_class = true
  end

  # @param [Hash] options
  def initialize(options)
    if !options.respond_to?(:deep_symbolize_keys)
      raise ArgumentError, "When assigning attributes, you must pass a hash as an argument."
    end
    @options = options.deep_symbolize_keys
    raise ArgumentError, "Table name is missing" unless @options[:table]
    if @options[:model_name]
      model_name = @options[:model_name]
    else
      model_name = @options[:table]
      if @options[:connection][:database]
        model_name = "#{@options[:connection][:database].gsub(/[^a-zA-Z]+/, '')}_#{model_name}"
      end
      model_name = model_name.classify
    end
    model_class_name = "#{self.class.to_s}::#{model_name}"
    eval <<-END
      class #{model_class_name} < AuthDatabase
        self.table_name = "#{@options[:table]}"
        self.inheritance_column = :_type_disabled
      end
    END

    @model = model_class_name.constantize
    @model.establish_connection @options[:connection]
  end

  def validate(username, password)
    user = @model.send("find_by_#{@options[:username_column]}!", username)
    password_from_database = user.send(@options[:password_column])

    if valid_password?(password, password_from_database)
      user_data(user)
    else
      false
    end

  rescue ActiveRecord::RecordNotFound
    false
  end

  def validate(username, password, site, user_agent)
    #without cutting out only the final class name the object has got no method defined by us in model.
    @model = "#{@options[:table].classify}".constantize
    #search users by their login or email + include site_name (exclude blocked accounts at first)
    user = @model.send("find_by_#{@options[:username_column]}_or_email!", username, site, true)
    user = @model.send("find_by_#{@options[:username_column]}_or_email!", username, site) if user.nil?
    user.service = site
    password_from_database = user.send(@options[:password_column])
    raise ActiveRecord::RecordNotFound if password.blank?
    if password_from_database.blank? && !user.old_passwords.unused.empty?
      valid_pass = nil
      user.old_passwords.unused.each do |pass|
        password_from_database = pass.password_hash
        if valid_old_password?(password, password_from_database, pass.password_type, pass.salt)
          valid_pass = pass
          break
        end
      end
      if !valid_pass.nil?
        valid_pass.overwrite_password! password
        user.renew_api_token
        user.create_magwet_accesses
        dev = user.add_device(user_agent)
        { username: user.send(@options[:username_column])||user.email, extra_attributes: extra_attributes(user), user: user, un: username, site: site, old_pw: true }
      else
        Rails.logger.warn "1"
        false
      end
    else
      if valid_password?(password, password_from_database)
        user.renew_api_token
        user.create_magwet_accesses
        dev = user.add_device(user_agent)
        { username: user.send(@options[:username_column])||user.email, extra_attributes: extra_attributes(user), user: user, un: username, site: site }
      else
        Rails.logger.warn "inside failed"
        dev = user.add_device(user_agent)
        user.log_login_failure(site, dev)
        user.is_minimal_user? ? {user: user, un: username, site: site } : false
      end
    end

  rescue ActiveRecord::RecordNotFound
    Rails.logger.warn "outside failed #{user_agent}"
    dev = UserDevice.add(user_agent)
    UserActivityLog.create(log_event: LogEvent.where(name:'login_failed').first,
      user_device: dev, value: I18n.t( "users.activity_logs.unknown_login_attempt", {username: username, site: site}),
      created_by_id: User.parent_user.id)
    false
  end

  def load_user_data(username)
    user = @model.send("find_by_#{@options[:username_column]}!", username)
    user_data(user)
  rescue ActiveRecord::RecordNotFound
    nil
  end

  private
  def user_data(user)
    { username: user.send(@options[:username_column]), extra_attributes: extra_attributes(user) }
  end

  def valid_password?(password, password_from_database)
    Rails.logger.warn "checking password in overwritten Class"
    return false if password_from_database.blank?
    magic = password_from_database.split('$')[1]
    case magic
    when /\A2a?\z/
      valid_password_with_bcrypt?(password, password_from_database)
    when /\AH\z/, /\AP\z/
      valid_password_with_phpass?(password, password_from_database)
    else
      valid_password_with_unix_crypt?(password, password_from_database)
    end
  end

  def valid_old_password?(password, password_from_database, password_format, password_salt)
    case password_format.to_i
    when OldPassword::Type['md5']
      valid_password_with_md5?(password, password_from_database)
    when OldPassword::Type['new_md5']
      valid_password_with_new_md5_alg?(password_salt+Digest::MD5.hexdigest(password), password_from_database)
    end
  end

  def valid_password_with_md5?(password, password_from_database)
    Digest::MD5.hexdigest(password) == password_from_database
  end

  def valid_password_with_new_md5_alg?(password, password_from_database)
    #not sure why but this salt needs to be here (not passed as a variable)
    #- otherwise the '#' is parsed to some different form and password doesnt match
    Digest::MD5.hexdigest(password+'++@#$%@***static part of salt***234@#$&$') == password_from_database
  end

  def valid_password_with_bcrypt?(password, password_from_database)
    password_with_pepper = password + @options[:pepper].to_s
    BCrypt::Password.new(password_from_database) == password_with_pepper
  end

  def valid_password_with_unix_crypt?(password, password_from_database)
    UnixCrypt.valid?(password, password_from_database)
  end

  def valid_password_with_phpass?(password, password_from_database)
    Phpass.new().check(password, password_from_database)
  end

  def extra_attributes(user)
    attributes = {}
    extra_attributes_option.each do |attribute_name, database_column|
      attributes[attribute_name] = user.send(database_column)
    end
    attributes
  end

  def extra_attributes_option
    @options[:extra_attributes] || {}
  end
end
